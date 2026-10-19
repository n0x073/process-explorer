#include "collector.h"
#include "procfs.h"

#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QRegularExpression>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <charconv>
#include <cstring>

using namespace pf;

static qint64 monoNs()
{
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return qint64(ts.tv_sec) * 1000000000 + ts.tv_nsec;
}

// All per-process reads go through a directory fd for /proc/PID. The fd pins that
// exact process: if it exits and the PID is reused while we are reading, further
// reads fail with ESRCH instead of silently returning another process's data.
static int readAt(int dirfd, const char *name, char *buf, int cap)
{
    int fd = ::openat(dirfd, name, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int total = 0;
    while (total < cap - 1) {
        ssize_t n = ::read(fd, buf + total, size_t(cap - 1 - total));
        if (n <= 0)
            break;
        total += int(n);
    }
    ::close(fd);
    buf[total] = 0;
    return total;
}

static QString readLinkAt(int dirfd, const char *name)
{
    char buf[4096];
    ssize_t n = ::readlinkat(dirfd, name, buf, sizeof buf - 1);
    return n < 0 ? QString() : QString::fromLocal8Bit(buf, int(n));
}

static int countFds(int dirfd)
{
    struct stat st;
    if (::fstatat(dirfd, "fd", &st, 0) != 0)
        return -1;
    if (st.st_size > 0) // Linux >= 6.2 reports the number of open fds here
        return int(st.st_size);
    int fd = ::openat(dirfd, "fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    DIR *d = fdopendir(fd); // takes ownership of fd
    if (!d) {
        ::close(fd);
        return -1;
    }
    int n = 0;
    while (dirent *e = readdir(d))
        if (e->d_name[0] != '.')
            ++n;
    closedir(d);
    return n;
}

// strtod() honours LC_NUMERIC, which QApplication sets from the user locale
// (de_DE: decimal comma) -> "1.07" would parse as 1. /proc always uses '.'.
static double parseDouble(const char *&p)
{
    while (*p == ' ' || *p == '\t')
        ++p;
    double v = 0;
    auto r = std::from_chars(p, p + strlen(p), v);
    p = r.ptr;
    return v;
}

static QString displayName(const QString &comm, const QString &exe, const QString &argv0)
{
    static const QRegularExpression sep(QStringLiteral("[\\\\/]"));
    for (const QString &cand : {exe, argv0}) {
        // argv0 may be rewritten by setproctitle ("avahi-daemon: running ...")
        QString base = cand.section(sep, -1).section(QLatin1String(": "), 0, 0).section(' ', 0, 0);
        if (!base.isEmpty() && base.startsWith(comm.left(15)))
            return base;
    }
    return comm;
}

Collector::Collector()
{
    m_ncpu = std::max(1, int(sysconf(_SC_NPROCESSORS_ONLN)));
    m_uid = getuid();
    m_gpuPath = findGpu();
    char buf[16384];
    if (readSmall("/proc/stat", buf, sizeof buf) > 0)
        if (const char *b = strstr(buf, "\nbtime "))
            m_btime = double(strtoll(b + 7, nullptr, 10));
    const auto blocks = QDir(QStringLiteral("/sys/block")).entryList(QDir::Dirs | QDir::NoDotAndDotDot | QDir::System);
    for (const QString &b : blocks)
        if (!b.startsWith(QLatin1String("loop")) && !b.startsWith(QLatin1String("ram"))
            && !b.startsWith(QLatin1String("zram")) && !b.startsWith(QLatin1String("dm-")))
            m_disks << b;
}

Collector::Static Collector::makeStatic(int dirfd, bool kthread, const QString &comm)
{
    Static s;
    s.comm = comm;
    struct stat st;
    if (::fstat(dirfd, &st) == 0)
        s.uid = st.st_uid;
    s.user = userName(s.uid);
    s.own = s.uid == m_uid;
    s.exe = readLinkAt(dirfd, "exe");
    if (s.exe.endsWith(QLatin1String(" (deleted)")))
        s.exe.chop(10);
    QByteArray raw(64 << 10, Qt::Uninitialized);
    int n = readAt(dirfd, "cmdline", raw.data(), int(raw.size()));
    raw.truncate(std::max(0, n));
    while (raw.endsWith('\0'))
        raw.chop(1);
    QString argv0 = QString::fromLocal8Bit(raw.left(raw.indexOf('\0') < 0 ? raw.size() : raw.indexOf('\0')));
    raw.replace('\0', ' ');
    s.cmdline = QString::fromLocal8Bit(raw);
    s.name = displayName(comm, s.exe, argv0);

    char cg[4096];
    if (readAt(dirfd, "cgroup", cg, sizeof cg) > 0) {
        if (char *p = strstr(cg, "0::")) {
            char *end = strchr(p, '\n');
            s.cgroup = QString::fromLocal8Bit(p + 3, end ? int(end - p - 3) : -1);
        }
    }
    const QStringList parts = s.cgroup.split('/', Qt::SkipEmptyParts);
    for (auto it = parts.crbegin(); it != parts.crend(); ++it)
        if (it->endsWith(QLatin1String(".service")) || it->endsWith(QLatin1String(".scope"))) {
            s.unit = *it;
            break;
        }
    if (kthread) {
        s.kind = Kind::KThread;
    } else {
        static const QRegularExpression fp(QStringLiteral("^app-flatpak-(.+)-\\d+\\.scope$"));
        for (const QString &part : parts) {
            auto m = fp.match(part);
            if (m.hasMatch()) {
                s.kind = Kind::Flatpak;
                s.flatpak = m.captured(1);
                break;
            }
        }
        if (s.kind == Kind::Normal && (s.cgroup.startsWith(QLatin1String("/system.slice/")) || s.cgroup == QLatin1String("/init.scope")))
            s.kind = Kind::Service;
    }
    return s;
}

void Collector::collect()
{
    auto snap = std::make_shared<Snapshot>();
    const qint64 now = monoNs();
    const double dt = m_lastNs ? double(now - m_lastNs) / 1e9 : 0.0;
    m_lastNs = now;
    snap->time = QDateTime::currentMSecsSinceEpoch() / 1000.0;

    QHash<quint64, Prev> nextPrev;
    nextPrev.reserve(m_prev.size() + 16);
    QVector<ProcInfo> &procs = snap->procs;
    procs.reserve(m_static.size() + 32);

    char buf[2048];
    DIR *proc = opendir("/proc");
    const int procfd = proc ? dirfd(proc) : -1;
    while (dirent *e = proc ? readdir(proc) : nullptr) {
        if (e->d_name[0] < '1' || e->d_name[0] > '9')
            continue;
        const int pid = atoi(e->d_name);
        const int pdir = ::openat(procfd, e->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (pdir < 0)
            continue;
        struct Closer { int fd; ~Closer() { ::close(fd); } } closer{pdir};
        if (readAt(pdir, "stat", buf, sizeof buf) <= 0)
            continue;
        char *l = strchr(buf, '('), *r = strrchr(buf, ')');
        if (!l || !r || r[1] == 0)
            continue;
        ProcInfo p;
        p.pid = pid;
        p.state = r[2];
        long long f[24] = {};
        char *q = r + 4;
        for (int i = 1; i < 24 && *q; ++i) // f[i] == stat field i+3
            f[i] = strtoll(q, &q, 10);
        p.ppid = int(f[1]);
        // PF_KTHREAD in stat field 9 ("flags"). Checking for kthreadd as parent (PID 2)
        // would misfire inside a container's PID namespace, where PID 2 is a normal process.
        constexpr unsigned long long PF_KTHREAD = 0x00200000;
        const bool kthread = (static_cast<unsigned long long>(f[6]) & PF_KTHREAD) != 0;
        quint64 ticks = quint64(f[11] + f[12]);
        p.utime = double(f[11]) / CLK_TCK;
        p.stime = double(f[12]) / CLK_TCK;
        p.nice = int(f[16]);
        p.threads = int(f[17]);
        p.start = quint64(f[19]);
        p.vms = f[20];
        p.rss = f[21] * PAGE_SIZE;
        p.key = (p.start << 22) | quint64(pid);
        p.ctime = m_btime + double(p.start) / CLK_TCK;

        auto sit = m_static.find(p.key);
        if (sit == m_static.end())
            sit = m_static.insert(p.key, makeStatic(pdir, kthread, QString::fromLocal8Bit(l + 1, int(r - l - 1))));
        const Static &s = *sit;
        p.name = s.name; p.comm = s.comm; p.exe = s.exe; p.cmdline = s.cmdline; p.user = s.user;
        p.cgroup = s.cgroup; p.unit = s.unit; p.flatpak = s.flatpak; p.uid = s.uid; p.kind = s.kind; p.own = s.own;
        if (p.kind == Kind::KThread) {
            p.vms = p.rss = -1;
        } else if (readAt(pdir, "statm", buf, sizeof buf) > 0) {
            // size resident shared ...: take resident and shared from the same
            // snapshot, otherwise resident - shared can come out negative
            char *m = buf;
            strtoll(m, &m, 10);
            p.rss = strtoll(m, &m, 10) * PAGE_SIZE;
            p.shared = strtoll(m, &m, 10) * PAGE_SIZE;
            p.priv = std::max<qint64>(0, p.rss - p.shared);
        }
        qint64 iot = -1;
        if (readAt(pdir, "io", buf, sizeof buf) > 0) {
            const char *rc = strstr(buf, "rchar: "), *wc = strstr(buf, "wchar: ");
            if (rc && wc) {
                p.ioR = strtoll(rc + 7, nullptr, 10);
                p.ioW = strtoll(wc + 7, nullptr, 10);
                iot = p.ioR + p.ioW;
            }
        }
        p.fds = countFds(pdir);

        auto pit = m_prev.constFind(p.key);
        if (pit != m_prev.constEnd() && dt > 0) {
            p.cpu = std::clamp(double(ticks - pit->ticks) / CLK_TCK / dt / m_ncpu * 100.0, 0.0, 100.0);
            if (iot >= 0 && pit->io >= 0)
                p.ioDelta = std::max(0.0, double(iot - pit->io) / dt);
        }
        nextPrev.insert(p.key, {ticks, iot});
        procs.push_back(std::move(p));
    }
    if (proc)
        closedir(proc);

    m_prev.swap(nextPrev);
    for (auto it = m_static.begin(); it != m_static.end();)
        it = m_prev.contains(it.key()) ? std::next(it) : m_static.erase(it);

    SysInfo &s = snap->sys;
    readSystem(s, dt);

    ProcInfo idle;
    idle.pid = 0;
    idle.ppid = -1;
    idle.key = 0;
    idle.name = QStringLiteral("System Idle Process");
    idle.kind = Kind::Idle;
    idle.cpu = s.idle;
    idle.threads = m_ncpu;
    idle.hasNice = false;
    idle.state = 'R';
    s.processes = procs.size();
    for (const ProcInfo &p : procs) {
        s.threads += p.threads;
        s.handles += std::max(0, p.fds);
    }
    procs.push_back(idle);
    emit ready(snap);
}

void Collector::readSystem(SysInfo &s, double dt)
{
    static char buf[65536];
    if (readSmall("/proc/stat", buf, sizeof buf) > 0) {
        QVector<CpuTimes> cur;
        quint64 ctx = 0, intr = 0;
        for (char *line = strtok(buf, "\n"); line; line = strtok(nullptr, "\n")) {
            if (strncmp(line, "cpu", 3) == 0) {
                char *q = line + 3;
                while (*q && *q != ' ')
                    ++q;
                quint64 v[10] = {};
                for (int i = 0; i < 10 && *q; ++i)
                    v[i] = strtoull(q, &q, 10);
                // user nice system idle iowait irq softirq steal guest guest_nice
                CpuTimes t;
                t.total = v[0] + v[1] + v[2] + v[3] + v[4] + v[5] + v[6] + v[7];
                t.idle = v[3] + v[4];
                t.iowait = v[4];
                t.kernel = v[2] + v[5] + v[6];
                cur.push_back(t);
            } else if (strncmp(line, "ctxt ", 5) == 0) {
                ctx = strtoull(line + 5, nullptr, 10);
            } else if (strncmp(line, "intr ", 5) == 0) {
                intr = strtoull(line + 5, nullptr, 10);
            }
        }
        auto pct = [](quint64 a, quint64 b, quint64 tot) { return tot ? 100.0 * double(a - b) / double(tot) : 0.0; };
        if (m_prevCpu.size() == cur.size() && !cur.isEmpty()) {
            for (int i = 0; i < cur.size(); ++i) {
                quint64 tot = cur[i].total - m_prevCpu[i].total;
                double idle = pct(cur[i].idle, m_prevCpu[i].idle, tot);
                if (i == 0) {
                    s.idle = tot ? idle : 100.0;
                    s.cpu = 100.0 - s.idle;
                    s.kernel = pct(cur[i].kernel, m_prevCpu[i].kernel, tot);
                    s.iowait = pct(cur[i].iowait, m_prevCpu[i].iowait, tot);
                } else {
                    s.percpu.push_back(tot ? 100.0 - idle : 0.0);
                }
            }
        } else {
            s.percpu.fill(0.0, std::max(0, int(cur.size()) - 1));
        }
        m_prevCpu = cur;
        if (dt > 0 && m_prevCtx) {
            s.ctx = double(ctx - m_prevCtx) / dt;
            s.intr = double(intr - m_prevIntr) / dt;
        }
        m_prevCtx = ctx;
        m_prevIntr = intr;
    }

    const auto mi = meminfo();
    s.memTotal = mi.value("MemTotal");
    s.memAvail = mi.value("MemAvailable");
    s.memUsed = s.memTotal - s.memAvail;
    s.physPct = s.memTotal ? 100.0 * s.memUsed / s.memTotal : 0;
    s.cached = mi.value("Cached");
    s.buffers = mi.value("Buffers");
    s.shmem = mi.value("Shmem");
    s.slab = mi.value("Slab");
    s.sreclaim = mi.value("SReclaimable");
    s.kstack = mi.value("KernelStack");
    s.pagetables = mi.value("PageTables");
    s.dirty = mi.value("Dirty");
    s.swapTotal = mi.value("SwapTotal");
    s.swapUsed = s.swapTotal - mi.value("SwapFree");
    s.swapPct = s.swapTotal ? 100.0 * s.swapUsed / s.swapTotal : 0;
    s.commit = mi.value("Committed_AS");
    // with heuristic overcommit (mode 0/1) CommitLimit is not enforced -> use RAM + swap like Windows
    bool strict = readText(QStringLiteral("/proc/sys/vm/overcommit_memory")).trimmed() == QLatin1String("2");
    s.commitLimit = std::max<qint64>(1, strict ? mi.value("CommitLimit") : s.memTotal + s.swapTotal);
    s.commitPct = std::min(100.0, 100.0 * s.commit / s.commitLimit);

    double up = 0;
    if (readSmall("/proc/uptime", buf, sizeof buf) > 0)
    {
        const char *q = buf;
        up = parseDouble(q);
    }
    s.boot = QDateTime::currentMSecsSinceEpoch() / 1000.0 - up;
    if (readSmall("/proc/loadavg", buf, sizeof buf) > 0) {
        const char *q = buf;
        for (double &l : s.load)
            l = parseDouble(q);
    }

    // disks: fields  major minor name rd_ios rd_merges rd_sectors rd_ticks wr_ios wr_merges wr_sectors ...
    quint64 disk[4] = {};
    if (readSmall("/proc/diskstats", buf, sizeof buf) > 0) {
        for (char *line = strtok(buf, "\n"); line; line = strtok(nullptr, "\n")) {
            char name[64];
            unsigned long long v[8];
            if (sscanf(line, "%*u %*u %63s %llu %llu %llu %llu %llu %llu %llu %llu", name,
                       &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]) != 9)
                continue;
            if (!m_disks.contains(QLatin1String(name)))
                continue;
            disk[0] += v[2] * 512; disk[1] += v[6] * 512; disk[2] += v[0]; disk[3] += v[4];
        }
    }
    quint64 net[2] = {};
    if (readSmall("/proc/net/dev", buf, sizeof buf) > 0) {
        for (char *line = strtok(buf, "\n"); line; line = strtok(nullptr, "\n")) {
            char *c = strchr(line, ':');
            if (!c)
                continue;
            char *n = line;
            while (*n == ' ')
                ++n;
            if (strncmp(n, "lo:", 3) == 0)
                continue;
            unsigned long long v[9];
            if (sscanf(c + 1, "%llu %*u %*u %*u %*u %*u %*u %*u %llu", &v[0], &v[8]) == 2) {
                net[0] += v[0];
                net[1] += v[8];
            }
        }
    }
    if (m_havePrevIo && dt > 0) {
        auto rate = [dt](quint64 a, quint64 b) { return a >= b ? double(a - b) / dt : 0.0; };
        s.diskR = rate(disk[0], m_prevDisk[0]);
        s.diskW = rate(disk[1], m_prevDisk[1]);
        s.diskROps = rate(disk[2], m_prevDisk[2]);
        s.diskWOps = rate(disk[3], m_prevDisk[3]);
        s.netRx = rate(net[0], m_prevNet[0]);
        s.netTx = rate(net[1], m_prevNet[1]);
    }
    s.diskTotR = qint64(disk[0]);
    s.diskTotW = qint64(disk[1]);
    s.netTotRx = qint64(net[0]);
    s.netTotTx = qint64(net[1]);
    memcpy(m_prevDisk, disk, sizeof disk);
    memcpy(m_prevNet, net, sizeof net);
    m_havePrevIo = true;

    if (!m_gpuPath.isEmpty()) {
        QByteArray p = m_gpuPath.toLocal8Bit();
        if (readSmall(p.constData(), buf, 64) > 0) {
            const char *q = buf;
            s.gpu = parseDouble(q);
        }
        QString dev = QFileInfo(m_gpuPath).path();
        s.vramUsed = readText(dev + "/mem_info_vram_used").trimmed().toLongLong();
        s.vramTotal = readText(dev + "/mem_info_vram_total").trimmed().toLongLong();
    }
}
