// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Process Exp contributors

#include "procfs.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLocale>
#include <QSet>
#include <QStandardPaths>
#include <QTextStream>

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <poll.h>
extern "C" { // this glibc header lacks __BEGIN_DECLS
#include <sys/pidfd.h>
}
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <map>

namespace pf {

const long CLK_TCK = sysconf(_SC_CLK_TCK);
const long PAGE_SIZE = sysconf(_SC_PAGESIZE);

int readSmall(const char *path, char *buf, int cap)
{
    int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int total = 0;
    while (total < cap - 1) {
        ssize_t n = ::read(fd, buf + total, cap - 1 - total);
        if (n <= 0)
            break;
        total += int(n);
    }
    ::close(fd);
    buf[total] = 0;
    return total;
}

QByteArray readFile(const QString &path, qint64 max)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Unbuffered))
        return {};
    QByteArray out;
    char buf[65536];
    while (out.size() < max) {
        qint64 n = f.read(buf, sizeof buf);
        if (n <= 0)
            break;
        out.append(buf, int(n));
    }
    return out;
}

QString readText(const QString &path) { return QString::fromUtf8(readFile(path)); }

QString readLink(const QString &path)
{
    char buf[4096];
    ssize_t n = ::readlink(path.toLocal8Bit().constData(), buf, sizeof buf - 1);
    if (n < 0)
        return {};
    return QString::fromLocal8Bit(buf, int(n));
}

QHash<QString, QString> parseStatus(int pid)
{
    QHash<QString, QString> out;
    const auto lines = readText(QStringLiteral("/proc/%1/status").arg(pid)).split('\n');
    for (const QString &l : lines) {
        int c = l.indexOf(':');
        if (c > 0)
            out.insert(l.left(c), l.mid(c + 1).trimmed());
    }
    return out;
}

qint64 kbField(const QHash<QString, QString> &st, const QString &key)
{
    auto it = st.find(key);
    if (it == st.end())
        return -1;
    bool ok = false;
    qint64 v = it->section(' ', 0, 0).toLongLong(&ok);
    return ok ? v * 1024 : -1;
}

QHash<QString, qint64> meminfo()
{
    QHash<QString, qint64> out;
    char buf[8192];
    if (readSmall("/proc/meminfo", buf, sizeof buf) < 0)
        return out;
    for (char *line = strtok(buf, "\n"); line; line = strtok(nullptr, "\n")) {
        char *c = strchr(line, ':');
        if (!c)
            continue;
        *c = 0;
        out.insert(QString::fromLatin1(line), strtoll(c + 1, nullptr, 10) * 1024);
    }
    return out;
}

static const char *const CAP_NAMES[] = {
    "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid",
    "setpcap", "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw",
    "ipc_lock", "ipc_owner", "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct",
    "sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time", "sys_tty_config", "mknod",
    "lease", "audit_write", "audit_control", "setfcap", "mac_override", "mac_admin", "syslog",
    "wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore"};

QStringList decodeCaps(const QString &hex)
{
    bool ok = false;
    quint64 v = hex.toULongLong(&ok, 16);
    QStringList out;
    if (!ok)
        return out;
    for (int i = 0; i < int(std::size(CAP_NAMES)); ++i)
        if (v >> i & 1)
            out << QStringLiteral("CAP_") + QString::fromLatin1(CAP_NAMES[i]).toUpper();
    return out;
}

QString userName(uint uid)
{
    static QHash<uint, QString> cache;
    auto it = cache.find(uid);
    if (it != cache.end())
        return *it;
    passwd *pw = getpwuid(uid);
    QString n = pw ? QString::fromLocal8Bit(pw->pw_name) : QString::number(uid);
    cache.insert(uid, n);
    return n;
}

QString groupName(uint gid)
{
    group *g = getgrgid(gid);
    return g ? QString::fromLocal8Bit(g->gr_name) : QString::number(gid);
}

QStringList cmdlineArgs(int pid)
{
    QByteArray raw = readFile(QStringLiteral("/proc/%1/cmdline").arg(pid));
    QStringList out;
    for (const QByteArray &a : raw.split('\0'))
        if (!a.isEmpty())
            out << QString::fromLocal8Bit(a);
    return out;
}

quint64 startTime(int pid)
{
    char path[48], buf[1024];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    if (readSmall(path, buf, sizeof buf) <= 0)
        return 0;
    char *p = strrchr(buf, ')');
    if (!p)
        return 0;
    p += 2; // state = field 3
    for (int field = 3; field < 22 && *p; ++field) {
        p = strchr(p, ' ');
        if (!p)
            return 0;
        ++p;
    }
    return strtoull(p, nullptr, 10);
}

int openPidfd(int pid, quint64 start)
{
    if (pid <= 0) {
        errno = ESRCH;
        return -1;
    }
    int fd = pidfd_open(pid, 0);
    if (fd < 0)
        return -1;
    // Opened first, verified second: if the PID was already reused before
    // pidfd_open, the start time differs and we refuse.
    if (start && startTime(pid) != start) {
        ::close(fd);
        errno = ESRCH;
        return -1;
    }
    return fd;
}

int sendSignal(int pidfd, int sig)
{
    return pidfd_send_signal(pidfd, sig, nullptr, 0) == 0 ? 0 : errno;
}

bool waitExit(int pidfd, int timeoutMs)
{
    pollfd p{pidfd, POLLIN, 0}; // a pidfd becomes readable when the process exits
    return poll(&p, 1, timeoutMs) > 0;
}

int signalProcess(int pid, quint64 start, int sig)
{
    int fd = openPidfd(pid, start);
    if (fd < 0)
        return errno;
    int e = sendSignal(fd, sig);
    ::close(fd);
    return e;
}

QString findGpu()
{
    QDir d(QStringLiteral("/sys/class/drm"));
    const auto cards = d.entryList({QStringLiteral("card*")}, QDir::Dirs | QDir::NoDotAndDotDot | QDir::System, QDir::Name);
    for (const QString &c : cards) {
        QString p = d.filePath(c + QStringLiteral("/device/gpu_busy_percent"));
        if (QFileInfo::exists(p))
            return p;
    }
    return {};
}

QStringList dataDirs(const QString &sub)
{
    QStringList bases = QStandardPaths::standardLocations(QStandardPaths::GenericDataLocation);
    bases << QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + QStringLiteral("/flatpak/exports/share")
          << QStringLiteral("/var/lib/flatpak/exports/share") << QStringLiteral("/var/lib/snapd/desktop");
    QStringList out;
    for (const QString &b : std::as_const(bases)) {
        const QString d = QDir::cleanPath(b + '/' + sub);
        if (!out.contains(d) && QFileInfo(d).isDir())
            out << d;
    }
    return out;
}

QVector<int> threadIds(int pid)
{
    QVector<int> out;
    QByteArray path = QStringLiteral("/proc/%1/task").arg(pid).toLatin1();
    if (DIR *d = opendir(path.constData())) {
        while (dirent *e = readdir(d))
            if (e->d_name[0] >= '0' && e->d_name[0] <= '9')
                out << atoi(e->d_name);
        closedir(d);
    }
    return out;
}

QVector<ThreadRow> readThreads(int pid)
{
    QVector<ThreadRow> rows;
    char buf[1024], path[96];
    for (int tid : threadIds(pid)) {
        snprintf(path, sizeof path, "/proc/%d/task/%d/stat", pid, tid);
        if (readSmall(path, buf, sizeof buf) <= 0)
            continue;
        char *l = strchr(buf, '('), *r = strrchr(buf, ')');
        if (!l || !r)
            continue;
        ThreadRow t{};
        t.tid = tid;
        t.name = QString::fromLocal8Bit(l + 1, int(r - l - 1));
        // fields after ')' : index 0 == field 3
        long long f[40] = {};
        char *p = r + 2;
        t.state = *p;
        p += 2;
        for (int i = 1; i < 40 && *p; ++i)
            f[i] = strtoll(p, &p, 10);
        t.ticks = quint64(f[11] + f[12]);
        t.utime = double(f[11]) / CLK_TCK;
        t.stime = double(f[12]) / CLK_TCK;
        t.prio = int(f[15]);
        t.nice = int(f[16]);
        t.cpu = int(f[36]);
        snprintf(path, sizeof path, "/proc/%d/task/%d/wchan", pid, tid);
        if (readSmall(path, buf, sizeof buf) > 0 && strcmp(buf, "0") != 0)
            t.wchan = QString::fromLatin1(buf);
        rows << t;
    }
    return rows;
}

static const char *tcpState(const QString &hex)
{
    static const char *const S[] = {"", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
                                    "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING"};
    int v = hex.toInt(nullptr, 16);
    return v > 0 && v < 12 ? S[v] : "";
}

static QString addr(const QString &hex, bool *any = nullptr)
{
    // /proc/net/* prints each 32 bit word in host (little endian) order
    int c = hex.indexOf(':');
    QByteArray b = QByteArray::fromHex(hex.left(c).toLatin1());
    int port = hex.mid(c + 1).toInt(nullptr, 16);
    unsigned char raw[16] = {};
    for (int w = 0; w < b.size() / 4; ++w)
        for (int i = 0; i < 4; ++i)
            raw[w * 4 + i] = uchar(b[w * 4 + 3 - i]);
    char out[INET6_ADDRSTRLEN] = "?";
    bool zero = std::all_of(raw, raw + b.size(), [](unsigned char x) { return x == 0; });
    QString s;
    static const unsigned char v4mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (b.size() == 4 || (b.size() == 16 && memcmp(raw, v4mapped, 12) == 0)) {
        inet_ntop(AF_INET, b.size() == 4 ? raw : raw + 12, out, sizeof out);
        s = QString::fromLatin1(out);
    } else {
        inet_ntop(AF_INET6, raw, out, sizeof out);
        s = '[' + QString::fromLatin1(out) + ']';
    }
    if (any)
        *any = zero;
    return s + ':' + QString::number(port);
}

template<typename F>
static void forEachInet(int pid, F &&fn)
{
    for (const char *proto : {"tcp", "tcp6", "udp", "udp6"}) {
        const auto lines = readText(QStringLiteral("/proc/%1/net/%2").arg(pid).arg(QLatin1String(proto))).split('\n');
        for (int i = 1; i < lines.size(); ++i) {
            const auto p = lines[i].simplified().split(' ');
            if (p.size() >= 10)
                fn(QString::fromLatin1(proto), p);
        }
    }
}

QHash<QString, QString> socketMap(int pid)
{
    QHash<QString, QString> m;
    forEachInet(pid, [&](const QString &proto, const QStringList &p) {
        QString d = proto.toUpper() + ' ' + addr(p[1]) + QStringLiteral(" -> ") + addr(p[2]);
        if (proto.startsWith(QLatin1String("tcp")))
            d += ' ' + QLatin1String(tcpState(p[3]));
        m.insert(p[9], d);
    });
    const auto lines = readText(QStringLiteral("/proc/%1/net/unix").arg(pid)).split('\n');
    for (int i = 1; i < lines.size(); ++i) {
        const auto p = lines[i].simplified().split(' ');
        if (p.size() >= 7)
            m.insert(p[6], QStringLiteral("UNIX ") + (p.size() > 7 ? p[7] : QStringLiteral("(unnamed)")));
    }
    return m;
}

QVector<HandleRow> readHandles(int pid, const QHash<QString, QString> *sockets)
{
    QVector<HandleRow> rows;
    char dirp[64], lp[384], target[4096];
    snprintf(dirp, sizeof dirp, "/proc/%d/fd", pid);
    DIR *d = opendir(dirp);
    if (!d)
        return rows;
    while (dirent *e = readdir(d)) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9')
            continue;
        snprintf(lp, sizeof lp, "%s/%s", dirp, e->d_name);
        ssize_t n = ::readlink(lp, target, sizeof target - 1);
        if (n < 0)
            continue;
        target[n] = 0;
        QString t = QString::fromLocal8Bit(target, int(n)), type;
        if (t.startsWith(QLatin1String("socket:["))) {
            type = QStringLiteral("Socket");
            if (sockets)
                t = sockets->value(t.mid(8, t.size() - 9), t);
        } else if (t.startsWith(QLatin1String("pipe:")))
            type = QStringLiteral("Pipe");
        else if (t.startsWith(QLatin1String("anon_inode:"))) {
            type = QStringLiteral("Anon Inode");
            t = t.mid(11);
        } else if (t.startsWith(QLatin1String("/memfd:")))
            type = QStringLiteral("Memfd");
        else if (t.startsWith(QLatin1String("/dev/")))
            type = QStringLiteral("Device");
        else if (t.startsWith('/')) {
            struct stat st;
            type = (::stat(target, &st) == 0 && S_ISDIR(st.st_mode)) ? QStringLiteral("Directory") : QStringLiteral("File");
        } else
            type = QStringLiteral("Other");
        rows.push_back({type, t, atoi(e->d_name)});
    }
    closedir(d);
    return rows;
}

QVector<MapRow> readMaps(int pid)
{
    struct G { quint64 base, size; bool exec; };
    std::map<QString, G> groups;
    const QByteArray data = readFile(QStringLiteral("/proc/%1/maps").arg(pid), 32 << 20);
    for (const QByteArray &ln : data.split('\n')) {
        int slash = ln.indexOf('/');
        if (slash < 0)
            continue;
        const char *s = ln.constData();
        char *e;
        quint64 a = strtoull(s, &e, 16);
        quint64 b = strtoull(e + 1, &e, 16);
        bool x = e[3] == 'x';
        QString path = QString::fromLocal8Bit(ln.mid(slash));
        auto it = groups.find(path);
        if (it == groups.end())
            groups.emplace(path, G{a, b - a, x});
        else {
            it->second.base = std::min(it->second.base, a);
            it->second.size += b - a;
            it->second.exec |= x;
        }
    }
    QVector<MapRow> rows;
    rows.reserve(int(groups.size()));
    for (auto &[path, g] : groups)
        rows.push_back({QFileInfo(path).fileName(), path, g.base, g.size,
                        g.exec ? QStringLiteral("Image") : QStringLiteral("Data")});
    return rows;
}

QVector<ConnRow> readConnections(int pid)
{
    QSet<QString> inodes;
    for (const auto &h : readHandles(pid, nullptr))
        if (h.type == QLatin1String("Socket"))
            inodes.insert(h.name.mid(8, h.name.size() - 9));
    QVector<ConnRow> rows;
    forEachInet(pid, [&](const QString &proto, const QStringList &p) {
        if (!inodes.contains(p[9]))
            return;
        bool anyRemote = false;
        QString remote = addr(p[2], &anyRemote);
        bool tcp = proto.startsWith(QLatin1String("tcp"));
        rows.push_back({proto.toUpper(), addr(p[1]), anyRemote && !tcp ? QString() : remote,
                        tcp ? QLatin1String(tcpState(p[3])) : QString()});
    });
    return rows;
}

// ------------------------------------------------------------------ formatting
static const QLocale &loc()
{
    static const QLocale l = QLocale::system();
    return l;
}

QString num(qint64 v) { return loc().toString(v); }
QString fdec(double v, int prec) { return loc().toString(v, 'f', prec); }
QString fmtK(qint64 b) { return b < 0 ? QString() : num(b / 1024) + QStringLiteral(" K"); }

QString fmtBytes(double n)
{
    static const char *const U[] = {"B", "KB", "MB", "GB", "TB"};
    int u = 0;
    while (std::abs(n) >= 1024 && u < 4) {
        n /= 1024;
        ++u;
    }
    return (u == 0 ? QString::number(qint64(n)) : fdec(n, 1)) + ' ' + QLatin1String(U[u]);
}

QString fmtRate(double n) { return n > 0 ? fmtBytes(n) + QStringLiteral("/s") : QString(); }

QString fmtCpu(double v)
{
    if (v <= 0)
        return {};
    if (v < 0.01)
        return QStringLiteral("< ") + fdec(0.01);
    return fdec(v);
}

QString fmtTime(double sec)
{
    qint64 ms = qRound64(sec * 1000);
    qint64 h = ms / 3600000;
    ms %= 3600000;
    int m = int(ms / 60000);
    ms %= 60000;
    int s = int(ms / 1000);
    ms %= 1000;
    return QStringLiteral("%1:%2:%3%4%5").arg(h).arg(m, 2, 10, QChar('0')).arg(s, 2, 10, QChar('0'))
        .arg(loc().decimalPoint()).arg(ms, 3, 10, QChar('0'));
}

QString fmtDateTime(double epoch)
{
    if (epoch <= 0)
        return {};
    return QDateTime::fromSecsSinceEpoch(qint64(epoch)).toString(QStringLiteral("dd.MM.yyyy HH:mm:ss"));
}

} // namespace pf

// ------------------------------------------------------------------ desktop files
static QHash<QString, QString> parseDesktop(const QString &path)
{
    QHash<QString, QString> e;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return e;
    QTextStream ts(&f);
    bool inEntry = false;
    while (!ts.atEnd()) {
        QString l = ts.readLine().trimmed();
        if (l.startsWith('[')) {
            if (inEntry)
                break;
            inEntry = l == QLatin1String("[Desktop Entry]");
            continue;
        }
        int eq = l.indexOf('=');
        if (!inEntry || eq <= 0)
            continue;
        QString k = l.left(eq);
        static const QSet<QString> keys = {"Name", "GenericName", "Comment", "Icon", "Exec", "StartupWMClass", "NoDisplay"};
        if (keys.contains(k) && !e.contains(k))
            e.insert(k, l.mid(eq + 1));
    }
    return e;
}

static QString execToken(const QString &ex)
{
    QString s = ex;
    s.replace('"', ' ');
    for (const QString &t : s.split(' ', Qt::SkipEmptyParts)) {
        if (t == QLatin1String("env") || (t.contains('=') && !t.startsWith('/')))
            continue;
        if (t == QLatin1String("flatpak") || t == QLatin1String("sh") || t == QLatin1String("bash"))
            return {};
        return QFileInfo(t).fileName().toLower();
    }
    return {};
}

DesktopIndex::DesktopIndex()
{
    // earlier dirs win (user overrides system), matching XDG lookup rules
    const QStringList dirs = pf::dataDirs(QStringLiteral("applications"));
    for (const QString &d : dirs) {
        const auto files = QDir(d).entryList({QStringLiteral("*.desktop")}, QDir::Files, QDir::Name);
        for (const QString &f : files) {
            auto e = parseDesktop(d + '/' + f);
            if (!e.contains(QStringLiteral("Name")))
                continue;
            int idx = m_entries.size();
            m_entries.push_back({e.value("Name"), e.value("Comment", e.value("GenericName")), e.value("Icon")});
            // A key can be claimed by several files (code.desktop and code-url-handler.desktop
            // both run "code"). Stronger evidence wins: file name > WM class > Exec command;
            // hidden helper entries (NoDisplay) lose ties. Equal rank: earlier dir wins.
            const QString stem = f.chopped(8);
            const int hidden = e.value("NoDisplay") == QLatin1String("true") ? 1 : 0;
            auto claim = [&](const QString &k, int rank) {
                if (k.isEmpty())
                    return;
                rank = rank * 2 + hidden;
                auto it = m_byKey.find(k);
                if (it == m_byKey.end())
                    m_byKey.insert(k, {idx, rank});
                else if (rank < it->rank)
                    *it = {idx, rank};
            };
            claim(QChar('@') + stem, 0);
            claim(stem.toLower(), 1);
            claim(stem.toLower().section('.', -1), 2);
            claim(e.value("StartupWMClass").toLower(), 3);
            claim(execToken(e.value("Exec")), 4);
        }
    }
}

const DesktopIndex::Entry *DesktopIndex::lookup(const QString &name, const QString &exe, const QString &flatpak) const
{
    if (!flatpak.isEmpty()) {
        auto it = m_byKey.find(QChar('@') + flatpak);
        if (it != m_byKey.end())
            return &m_entries[it->idx];
    }
    for (const QString &c0 : {QFileInfo(exe).fileName(), name}) {
        QString c = c0.toLower();
        if (c.isEmpty())
            continue;
        QString variants[] = {c, c.endsWith(QLatin1String("-bin")) ? c.chopped(4) : QString(),
                              c.endsWith(QLatin1String("-wrapped")) ? c.chopped(8) : QString(), c.section('-', 0, 0)};
        for (const QString &v : variants) {
            if (v.isEmpty())
                continue;
            auto it = m_byKey.find(v);
            if (it != m_byKey.end())
                return &m_entries[it->idx];
        }
    }
    return nullptr;
}
