#include "dialogs.h"
#include "mainwindow.h"
#include "widgets.h"

#include <QApplication>
#include <QCheckBox>
#include <QColorDialog>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QRadioButton>
#include <QSortFilterProxyModel>
#include <QStandardPaths>
#include <QTabWidget>
#include <QTableView>
#include <QTreeWidget>
#include <QUrl>
#include <QVBoxLayout>

#include <QRegularExpression>

#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <sys/resource.h>
#include <unistd.h>

#include <ctime>

using namespace pf;

QTableView *makeTable(ListModel *model, int sortCol, Qt::SortOrder order)
{
    auto *view = new QTableView;
    auto *proxy = new QSortFilterProxyModel(view);
    proxy->setSourceModel(model);
    proxy->setSortRole(SortRole);
    view->setModel(proxy);
    view->setSortingEnabled(true);
    view->sortByColumn(sortCol, order);
    view->setSelectionBehavior(QAbstractItemView::SelectRows);
    view->setEditTriggers(QAbstractItemView::NoEditTriggers);
    view->verticalHeader()->hide();
    view->verticalHeader()->setDefaultSectionSize(20);
    view->setWordWrap(false);
    view->horizontalHeader()->setStretchLastSection(true);
    return view;
}

static QLineEdit *roLine(const QString &t)
{
    auto *e = new QLineEdit(t);
    e->setReadOnly(true);
    return e;
}

static qint64 monoNs()
{
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return qint64(ts.tv_sec) * 1000000000 + ts.tv_nsec;
}

// ================================================================== Properties
PropertiesDialog::PropertiesDialog(MainWindow *main, Node *n)
    : QDialog(main), m_main(main), m_key(n->key), m_pid(n->pid), m_name(n->info.name)
{
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle(QStringLiteral("%1:%2 Properties").arg(m_name).arg(m_pid));
    resize(720, 620);
    m_tabs = new QTabWidget;
    m_tabs->addTab(imageTab(n), tr("Image"));
    m_tabs->addTab(perfTab(), tr("Performance"));
    m_tabs->addTab(graphTab(n), tr("Performance Graph"));
    m_tabs->addTab(threadsTab(), tr("Threads"));
    m_tabs->addTab(tcpTab(), tr("TCP/IP"));
    m_tabs->addTab(securityTab(), tr("Security"));
    m_tabs->addTab(envTab(), tr("Environment"));
    m_tabs->addTab(stringsTab(), tr("Strings"));
    connect(m_tabs, &QTabWidget::currentChanged, this, &PropertiesDialog::refresh);
    auto *bb = new QDialogButtonBox(QDialogButtonBox::Ok);
    connect(bb, &QDialogButtonBox::accepted, this, &QDialog::close);
    auto *lay = new QVBoxLayout(this);
    lay->addWidget(m_tabs);
    lay->addWidget(bb);
    connect(main, &MainWindow::ticked, this, &PropertiesDialog::refresh);
    refresh();
}

QWidget *PropertiesDialog::imageTab(Node *n)
{
    auto *w = new QWidget;
    auto *lay = new QVBoxLayout(w);
    const ProcInfo &i = n->info;
    auto *head = new QHBoxLayout;
    auto *ic = new QLabel;
    ic->setPixmap(n->icon.pixmap(48, 48));
    head->addWidget(ic);
    head->addWidget(new QLabel(QStringLiteral("<b style='font-size:13pt'>%1</b><br>%2")
                                   .arg((n->desc.isEmpty() ? i.name : n->desc).toHtmlEscaped(), n->comment.toHtmlEscaped())), 1);
    lay->addLayout(head);

    auto *box = new QGroupBox(tr("Image File"));
    auto *f = new QFormLayout(box);
    auto *pathRow = new QHBoxLayout;
    pathRow->addWidget(roLine(i.exe), 1);
    auto *explore = new QPushButton(tr("Explore"));
    explore->setEnabled(!i.exe.isEmpty());
    const QString exe = i.exe;
    connect(explore, &QPushButton::clicked, this, [exe] { QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(exe).path())); });
    pathRow->addWidget(explore);
    f->addRow(tr("Path:"), pathRow);
    auto *cmd = new QPlainTextEdit(i.cmdline);
    cmd->setReadOnly(true);
    cmd->setMaximumHeight(60);
    f->addRow(tr("Command line:"), cmd);
    f->addRow(tr("Current directory:"), roLine(readLink(QStringLiteral("/proc/%1/cwd").arg(m_pid))));
    QString parentName = readText(QStringLiteral("/proc/%1/comm").arg(i.ppid)).trimmed();
    f->addRow(tr("Parent:"), roLine(QStringLiteral("%1(%2)").arg(parentName.isEmpty() ? QStringLiteral("<Non-existent Process>") : parentName).arg(i.ppid)));
    f->addRow(tr("User:"), roLine(i.user));
    f->addRow(tr("Started:"), roLine(fmtDateTime(i.ctime)));
    f->addRow(tr("Systemd Unit:"), roLine(i.unit));
    f->addRow(tr("Control Group:"), roLine(i.cgroup));
    if (!i.flatpak.isEmpty())
        f->addRow(tr("Flatpak App:"), roLine(i.flatpak));
    QString tty = readLink(QStringLiteral("/proc/%1/fd/0").arg(m_pid));
    f->addRow(tr("Terminal:"), roLine(tty.startsWith(QLatin1String("/dev/pts")) || tty.startsWith(QLatin1String("/dev/tty")) ? tty : QString()));
    auto *ver = new QHBoxLayout;
    m_pkg = new QLabel;
    m_pkg->setTextInteractionFlags(Qt::TextSelectableByMouse);
    auto *vb = new QPushButton(tr("Verify"));
    vb->setEnabled(!i.exe.isEmpty());
    connect(vb, &QPushButton::clicked, this, [this, exe] { verify(exe); });
    ver->addWidget(m_pkg, 1);
    ver->addWidget(vb);
    f->addRow(tr("Package:"), ver);
    lay->addWidget(box);

    auto *btns = new QHBoxLayout;
    btns->addStretch(1);
    m_suspend = new QPushButton(tr("Suspend"));
    connect(m_suspend, &QPushButton::clicked, this, [this] {
        if (Node *n = m_main->model()->node(m_key))
            m_main->suspendProcess(m_key, !n->info.stopped());
    });
    auto *kill = new QPushButton(tr("Kill Process"));
    connect(kill, &QPushButton::clicked, this, [this] { m_main->killProcess(m_key, m_name, false, SIGKILL); });
    btns->addWidget(m_suspend);
    btns->addWidget(kill);
    lay->addLayout(btns);
    lay->addStretch(1);
    return w;
}

void PropertiesDialog::verify(const QString &exe)
{
    QStringList out;
    auto run = [](const QString &prog, const QStringList &args, int *rc) {
        QProcess p;
        p.start(prog, args);
        p.waitForFinished(30000);
        *rc = p.exitCode();
        return QString::fromLocal8Bit(p.readAllStandardOutput() + p.readAllStandardError()).trimmed();
    };
    int rc = 0;
    if (!QStandardPaths::findExecutable("rpm").isEmpty()) {
        out << run("rpm", {"-qf", exe}, &rc);
        if (rc == 0) {
            QString v = run("rpm", {"-Vf", exe}, &rc);
            QString bad;
            for (const QString &l : v.split('\n'))
                if (l.endsWith(exe))
                    bad = l.section(' ', 0, 0);
            out << (bad.isEmpty() ? tr("(Verified)") : tr("(MODIFIED: %1)").arg(bad));
        }
    } else if (!QStandardPaths::findExecutable("dpkg").isEmpty()) {
        out << run("dpkg", {"-S", exe}, &rc);
    }
    m_pkg->setText(out.isEmpty() ? tr("No package manager found") : out.join(' '));
}

QWidget *PropertiesDialog::perfTab()
{
    auto *w = new QWidget;
    auto *g = new QGridLayout(w);
    auto group = [&](const QString &title, const QStringList &keys, int r, int c) {
        auto *box = new QGroupBox(title);
        auto *f = new QFormLayout(box);
        for (const QString &k : keys) {
            auto *l = new QLabel;
            l->setAlignment(Qt::AlignRight);
            f->addRow(k, l);
            m_perf.insert(k, l);
        }
        g->addWidget(box, r, c);
    };
    group(tr("CPU"), {"Priority (Nice)", "Kernel Time", "User Time", "Total Time", "CPU Usage",
                      "Voluntary Ctx Switches", "Involuntary Ctx Switches"}, 0, 0);
    group(tr("Virtual Memory"), {"Private Bytes", "Virtual Size", "Peak Virtual Size", "Swap",
                                 "Page Faults (minor)", "Page Faults (major)"}, 0, 1);
    group(tr("Physical Memory"), {"Working Set", "Peak Working Set", "WS Anonymous", "WS File", "WS Shared Memory"}, 1, 0);
    group(tr("I/O"), {"Read Ops", "Read Bytes", "Write Ops", "Write Bytes", "Disk Read Bytes", "Disk Write Bytes"}, 1, 1);
    group(tr("Handles"), {"Open FDs", "FD Limit (soft/hard)", "Threads"}, 2, 0);
    g->setRowStretch(3, 1);
    return w;
}

void PropertiesDialog::refreshPerf(Node *n)
{
    const ProcInfo &i = n->info;
    const auto st = parseStatus(m_pid);
    auto set = [this](const char *k, const QString &v) { m_perf.value(QLatin1String(k))->setText(v); };
    set("Priority (Nice)", QString::number(i.nice));
    set("Kernel Time", fmtTime(i.stime));
    set("User Time", fmtTime(i.utime));
    set("Total Time", fmtTime(i.cputime()));
    set("CPU Usage", i.cpu > 0 ? fmtCpu(i.cpu) : QStringLiteral("0"));
    set("Voluntary Ctx Switches", num(st.value("voluntary_ctxt_switches").toLongLong()));
    set("Involuntary Ctx Switches", num(st.value("nonvoluntary_ctxt_switches").toLongLong()));
    set("Private Bytes", fmtK(i.priv));
    set("Virtual Size", fmtK(i.vms));
    set("Peak Virtual Size", fmtK(kbField(st, "VmPeak")));
    set("Swap", fmtK(kbField(st, "VmSwap")));
    QString stat = readText(QStringLiteral("/proc/%1/stat").arg(m_pid));
    const auto fields = stat.mid(stat.lastIndexOf(')') + 2).split(' ');
    if (fields.size() > 9) {
        set("Page Faults (minor)", num(fields[7].toLongLong()));
        set("Page Faults (major)", num(fields[9].toLongLong()));
    }
    set("Working Set", fmtK(i.rss));
    set("Peak Working Set", fmtK(kbField(st, "VmHWM")));
    set("WS Anonymous", fmtK(kbField(st, "RssAnon")));
    set("WS File", fmtK(kbField(st, "RssFile")));
    set("WS Shared Memory", fmtK(kbField(st, "RssShmem")));
    QHash<QString, qint64> io;
    for (const QString &l : readText(QStringLiteral("/proc/%1/io").arg(m_pid)).split('\n'))
        if (l.contains(':'))
            io.insert(l.section(':', 0, 0), l.section(':', 1).trimmed().toLongLong());
    const QString na = tr("n/a");
    set("Read Ops", io.isEmpty() ? na : num(io.value("syscr")));
    set("Write Ops", io.isEmpty() ? na : num(io.value("syscw")));
    set("Read Bytes", io.isEmpty() ? na : fmtBytes(double(io.value("rchar"))));
    set("Write Bytes", io.isEmpty() ? na : fmtBytes(double(io.value("wchar"))));
    set("Disk Read Bytes", io.isEmpty() ? na : fmtBytes(double(io.value("read_bytes"))));
    set("Disk Write Bytes", io.isEmpty() ? na : fmtBytes(double(io.value("write_bytes"))));
    set("Open FDs", i.fds < 0 ? na : num(i.fds));
    rlimit rl;
    set("FD Limit (soft/hard)", prlimit(m_pid, RLIMIT_NOFILE, nullptr, &rl) == 0
                                    ? QStringLiteral("%1 / %2").arg(rl.rlim_cur).arg(rl.rlim_max) : na);
    set("Threads", QString::number(i.threads));
}

QWidget *PropertiesDialog::graphTab(Node *n)
{
    auto *w = new QWidget;
    auto *lay = new QVBoxLayout(w);
    struct D { QString title; FRing Node::*ring; QColor c; double max; std::function<QString(double)> fmt; };
    const D defs[] = {
        {tr("CPU Usage"), &Node::hCpu, pal::Cpu, 100, [](double v) { return fdec(v) + '%'; }},
        {tr("Private Bytes"), &Node::hPriv, pal::Phys, 0, [](double v) { return fmtBytes(v); }},
        {tr("Working Set"), &Node::hWs, pal::Phys, 0, [](double v) { return fmtBytes(v); }},
        {tr("I/O Bytes/s"), &Node::hIo, pal::Read, 0, [](double v) { return fmtBytes(v) + "/s"; }},
    };
    for (const D &d : defs) {
        auto *g = new Graph(d.max, d.title, 90);
        const FRing *r = &(n->*d.ring);
        g->addSeries(r, d.c);
        // node may die while the dialog is open -> look the ring up again each time
        ProcessModel *model = m_main->model();
        quint64 key = m_key;
        auto ring = d.ring;
        auto fmt = d.fmt;
        g->valueFn = [model, key, ring, fmt] {
            Node *nn = model->node(key);
            return nn && !(nn->*ring).empty() ? fmt((nn->*ring).back()) : QString();
        };
        g->tooltipFn = [model, key, ring, fmt](int b) {
            Node *nn = model->node(key);
            return nn && b < (nn->*ring).size() ? fmt((nn->*ring).back(b)) : QString();
        };
        lay->addWidget(g, 1);
        m_graphs << g;
    }
    return w;
}

QWidget *PropertiesDialog::threadsTab()
{
    auto *w = new QWidget;
    auto *lay = new QVBoxLayout(w);
    m_thrModel = new ListModel({"TID", "CPU", "Name", "State", "Priority", "Nice", "Kernel Time",
                                "User Time", "Processor", "Wait Channel"}, this);
    m_thrModel->setNumeric({0, 1, 4, 5, 6, 7, 8});
    m_thrModel->setFormatter(1, [](const QVariant &v) { return fmtCpu(v.toDouble()); });
    m_thrModel->setFormatter(6, [](const QVariant &v) { return fmtTime(v.toDouble()); });
    m_thrModel->setFormatter(7, [](const QVariant &v) { return fmtTime(v.toDouble()); });
    lay->addWidget(makeTable(m_thrModel, 1, Qt::DescendingOrder), 1);
    m_thrCount = new QLabel;
    lay->addWidget(m_thrCount);
    return w;
}

void PropertiesDialog::refreshThreads()
{
    const qint64 now = monoNs();
    const double dt = m_thrPrevNs ? double(now - m_thrPrevNs) / 1e9 : 0;
    m_thrPrevNs = now;
    const long ncpu = std::max(1L, sysconf(_SC_NPROCESSORS_ONLN));
    QHash<int, quint64> next;
    QVector<ListModel::Row> rows;
    for (const ThreadRow &t : readThreads(m_pid)) {
        double cpu = 0;
        auto it = m_thrPrev.constFind(t.tid);
        if (it != m_thrPrev.constEnd() && dt > 0)
            cpu = std::max(0.0, double(t.ticks - *it) / CLK_TCK / dt / ncpu * 100);
        next.insert(t.tid, t.ticks);
        rows.push_back({t.tid, cpu, t.name, QString(QChar(t.state)), t.prio, t.nice, t.stime, t.utime, t.cpu, t.wchan});
    }
    m_thrPrev.swap(next);
    m_thrCount->setText(tr("Count: %1").arg(rows.size()));
    m_thrModel->setRows(std::move(rows));
}

QWidget *PropertiesDialog::tcpTab()
{
    auto *w = new QWidget;
    auto *lay = new QVBoxLayout(w);
    m_tcpModel = new ListModel({"Protocol", "Local Address", "Remote Address", "State"}, this);
    auto *v = makeTable(m_tcpModel, 0);
    v->setColumnWidth(1, 220);
    v->setColumnWidth(2, 220);
    lay->addWidget(v, 1);
    return w;
}

void PropertiesDialog::refreshTcp()
{
    QVector<ListModel::Row> rows;
    for (const ConnRow &c : readConnections(m_pid))
        rows.push_back({c.proto, c.local, c.remote, c.state});
    m_tcpModel->setRows(std::move(rows));
}

QWidget *PropertiesDialog::securityTab()
{
    auto *w = new QWidget;
    auto *lay = new QVBoxLayout(w);
    const auto st = parseStatus(m_pid);
    auto *info = new QTreeWidget;
    info->setHeaderLabels({tr("Property"), tr("Value")});
    info->setRootIsDecorated(false);
    auto add = [info](const QString &k, const QString &v) { new QTreeWidgetItem(info, {k, v}); };
    auto ids = [&](const char *field, QString (*name)(uint)) {
        QStringList out;
        for (const QString &v : st.value(field).split(QRegularExpression("\\s+"), Qt::SkipEmptyParts))
            out << QStringLiteral("%1(%2)").arg(name(v.toUInt()), v);
        return out.join(QStringLiteral(", "));
    };
    add(tr("User (real, eff, saved, fs)"), ids("Uid", userName));
    add(tr("Group (real, eff, saved, fs)"), ids("Gid", groupName));
    QStringList groups;
    for (const QString &g : st.value("Groups").split(' ', Qt::SkipEmptyParts))
        groups << groupName(g.toUInt());
    add(tr("Supplementary Groups"), groups.join(QStringLiteral(", ")));
    QString se = readText(QStringLiteral("/proc/%1/attr/current").arg(m_pid));
    se.remove(QChar('\0'));
    add(tr("SELinux Context"), se.trimmed());
    add(tr("No New Privileges"), st.value("NoNewPrivs"));
    static const QHash<QString, QString> sc = {{"0", "disabled"}, {"1", "strict"}, {"2", "filter"}};
    add(tr("Seccomp"), sc.value(st.value("Seccomp"), st.value("Seccomp")));
    const auto nss = QDir("/proc/self/ns").entryList(QDir::System | QDir::NoDotAndDotDot, QDir::Name);
    for (const QString &ns : nss) {
        QString mine = readLink("/proc/self/ns/" + ns), theirs = readLink(QStringLiteral("/proc/%1/ns/").arg(m_pid) + ns);
        if (!theirs.isEmpty())
            add(tr("Namespace %1").arg(ns), theirs + (mine == theirs ? QString() : tr("   (isolated)")));
    }
    info->resizeColumnToContents(0);
    lay->addWidget(info, 1);

    auto *caps = new QTreeWidget;
    caps->setHeaderLabels({tr("Capability"), tr("Effective"), tr("Permitted"), tr("Inheritable"), tr("Bounding"), tr("Ambient")});
    caps->setRootIsDecorated(false);
    QVector<QSet<QString>> sets;
    QSet<QString> all;
    for (const char *k : {"CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"}) {
        const auto l = decodeCaps(st.value(k));
        sets << QSet<QString>(l.begin(), l.end());
        all.unite(sets.last());
    }
    QStringList sorted(all.begin(), all.end());
    sorted.sort();
    for (const QString &c : sorted) {
        QStringList row{c};
        for (const auto &s : sets)
            row << (s.contains(c) ? QStringLiteral("✔") : QString());
        new QTreeWidgetItem(caps, row);
    }
    caps->resizeColumnToContents(0);
    lay->addWidget(new QLabel(tr("Capabilities:")));
    lay->addWidget(caps, 2);
    return w;
}

QWidget *PropertiesDialog::envTab()
{
    auto *w = new QWidget;
    auto *lay = new QVBoxLayout(w);
    auto *m = new ListModel({"Variable", "Value"}, this);
    QByteArray raw = readFile(QStringLiteral("/proc/%1/environ").arg(m_pid));
    if (raw.isEmpty() && access(QStringLiteral("/proc/%1/environ").arg(m_pid).toLocal8Bit().constData(), R_OK) != 0)
        lay->addWidget(new QLabel(tr("Access denied.")));
    QVector<ListModel::Row> rows;
    for (const QByteArray &e : raw.split('\0')) {
        int eq = e.indexOf('=');
        if (eq > 0)
            rows.push_back({QString::fromLocal8Bit(e.left(eq)), QString::fromLocal8Bit(e.mid(eq + 1))});
    }
    m->setRows(std::move(rows));
    auto *v = makeTable(m, 0);
    v->setColumnWidth(0, 220);
    lay->addWidget(v, 1);
    return w;
}

QWidget *PropertiesDialog::stringsTab()
{
    auto *w = new QWidget;
    auto *lay = new QVBoxLayout(w);
    auto *top = new QHBoxLayout;
    m_strImage = new QRadioButton(tr("Image"));
    auto *mem = new QRadioButton(tr("Memory"));
    m_strImage->setChecked(true);
    connect(m_strImage, &QRadioButton::toggled, this, [this] { loadStrings(); });
    top->addWidget(m_strImage);
    top->addWidget(mem);
    top->addStretch(1);
    m_strFind = new QLineEdit;
    m_strFind->setPlaceholderText(tr("Find…"));
    connect(m_strFind, &QLineEdit::returnPressed, this, [this] {
        if (!m_strText->find(m_strFind->text())) {
            m_strText->moveCursor(QTextCursor::Start);
            m_strText->find(m_strFind->text());
        }
    });
    top->addWidget(m_strFind);
    auto *save = new QPushButton(tr("Save…"));
    connect(save, &QPushButton::clicked, this, [this] {
        QString fn = QFileDialog::getSaveFileName(this, tr("Save Strings"), m_name + ".txt");
        QFile f(fn);
        if (!fn.isEmpty() && f.open(QIODevice::WriteOnly))
            f.write(m_strText->toPlainText().toUtf8());
    });
    top->addWidget(save);
    lay->addLayout(top);
    m_strText = new QPlainTextEdit;
    m_strText->setReadOnly(true);
    m_strText->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    m_strText->setLineWrapMode(QPlainTextEdit::NoWrap);
    lay->addWidget(m_strText, 1);
    return w;
}

static void extractStrings(const char *d, qint64 n, QByteArray &out, int &count)
{
    qint64 start = -1;
    for (qint64 i = 0; i <= n; ++i) {
        bool pr = i < n && uchar(d[i]) >= 0x20 && uchar(d[i]) < 0x7f;
        if (pr && start < 0)
            start = i;
        else if (!pr && start >= 0) {
            if (i - start >= 5 && count < 300000) {
                out.append(d + start, int(i - start)).append('\n');
                ++count;
            }
            start = -1;
        }
    }
}

void PropertiesDialog::loadStrings()
{
    m_stringsLoaded = true;
    constexpr qint64 limit = 64LL << 20;
    QByteArray out;
    int count = 0;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    if (m_strImage->isChecked()) {
        Node *n = m_main->model()->node(m_key);
        QString exe = n && !n->info.exe.isEmpty() ? n->info.exe : QStringLiteral("/proc/%1/exe").arg(m_pid);
        QFile f(exe);
        if (f.open(QIODevice::ReadOnly)) {
            QByteArray d = f.read(limit);
            extractStrings(d.constData(), d.size(), out, count);
        } else {
            out = "Error: " + f.errorString().toUtf8();
        }
    } else {
        int fd = ::open(QStringLiteral("/proc/%1/mem").arg(m_pid).toLocal8Bit().constData(), O_RDONLY);
        if (fd < 0) {
            out = "Error: " + QByteArray(strerror(errno)) +
                  "\n\nMemory strings need ptrace permission (same user and kernel.yama.ptrace_scope=0, or root).";
        } else {
            qint64 total = 0;
            QByteArray buf;
            const auto maps = readFile(QStringLiteral("/proc/%1/maps").arg(m_pid)).split('\n');
            for (const QByteArray &ln : maps) {
                const auto p = ln.simplified().split(' ');
                if (p.size() < 5 || !p[1].startsWith('r'))
                    continue;
                if (p.size() > 5 && (p[5].startsWith('/') || p[5].startsWith("[vvar") || p[5] == "[vsyscall]"))
                    continue;
                bool ok;
                const QByteArray range = p[0];
                const int dash = range.indexOf('-');
                quint64 a = range.left(dash).toULongLong(&ok, 16);
                quint64 b = range.mid(dash + 1).toULongLong(&ok, 16);
                qint64 size = std::min<qint64>(qint64(b - a), limit - total);
                if (size <= 0)
                    break;
                buf.resize(size);
                ssize_t r = pread(fd, buf.data(), size_t(size), off_t(a));
                if (r <= 0)
                    continue;
                total += r;
                extractStrings(buf.constData(), r, out, count);
            }
            ::close(fd);
        }
    }
    QApplication::restoreOverrideCursor();
    m_strText->setPlainText(QString::fromLatin1(out));
}

void PropertiesDialog::refresh()
{
    Node *n = m_main->model()->node(m_key);
    if (!n || n->state == Node::Dying) {
        setWindowTitle(QStringLiteral("%1:%2 Properties (exited)").arg(m_name).arg(m_pid));
        return;
    }
    m_suspend->setText(n->info.stopped() ? tr("Resume") : tr("Suspend"));
    switch (m_tabs->currentIndex()) {
    case 1: refreshPerf(n); break;
    case 2: for (Graph *g : std::as_const(m_graphs)) g->advance(); break;
    case 3: refreshThreads(); break;
    case 4: refreshTcp(); break;
    case 7: if (!m_stringsLoaded) loadStrings(); break;
    }
}

// ================================================================== Find
FindDialog::FindDialog(MainWindow *main) : QDialog(main), m_main(main)
{
    setWindowTitle(tr("Process Explorer Search"));
    resize(820, 460);
    auto *lay = new QVBoxLayout(this);
    auto *top = new QHBoxLayout;
    top->addWidget(new QLabel(tr("Handle or DLL substring:")));
    m_edit = new QLineEdit;
    connect(m_edit, &QLineEdit::returnPressed, this, &FindDialog::search);
    top->addWidget(m_edit, 1);
    m_btn = new QPushButton(tr("Search"));
    connect(m_btn, &QPushButton::clicked, this, &FindDialog::search);
    top->addWidget(m_btn);
    m_cancel = new QPushButton(tr("Cancel"));
    m_cancel->setEnabled(false);
    connect(m_cancel, &QPushButton::clicked, this, [this] { m_stop = true; });
    top->addWidget(m_cancel);
    lay->addLayout(top);
    m_model = new ListModel({"Process", "PID", "Type", "Name"}, this);
    m_model->setNumeric({1});
    m_view = makeTable(m_model);
    m_view->setColumnWidth(0, 160);
    m_view->setColumnWidth(2, 90);
    connect(m_view, &QTableView::doubleClicked, this, [this](const QModelIndex &idx) {
        auto *proxy = static_cast<QSortFilterProxyModel *>(m_view->model());
        const auto &row = m_model->rows()[proxy->mapToSource(idx).row()];
        m_main->selectPid(row[1].toInt(), row[2].toString() == QLatin1String("DLL") ? MainWindow::LowerDlls : MainWindow::LowerHandles);
    });
    lay->addWidget(m_view, 1);
    m_status = new QLabel;
    lay->addWidget(m_status);
}

void FindDialog::focusEdit()
{
    m_edit->setFocus();
    m_edit->selectAll();
}

void FindDialog::search()
{
    const QString needle = m_edit->text().trimmed();
    if (needle.isEmpty())
        return;
    m_stop = false;
    m_btn->setEnabled(false);
    m_cancel->setEnabled(true);
    QVector<ListModel::Row> rows;
    const auto pids = QDir("/proc").entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    int k = 0;
    for (const QString &ps : pids) {
        bool ok;
        int pid = ps.toInt(&ok);
        if (!ok)
            continue;
        if (m_stop)
            break;
        if (++k % 20 == 0) {
            m_status->setText(tr("Searching… %1").arg(k));
            QApplication::processEvents();
        }
        QString name = readText(QStringLiteral("/proc/%1/comm").arg(pid)).trimmed();
        for (const HandleRow &h : readHandles(pid, nullptr))
            if (h.name.contains(needle, Qt::CaseInsensitive))
                rows.push_back({name, pid, h.type, h.name});
        for (const MapRow &m : readMaps(pid))
            if (m.path.contains(needle, Qt::CaseInsensitive))
                rows.push_back({name, pid, QStringLiteral("DLL"), m.path});
    }
    m_status->setText(tr("%1 matching items.").arg(rows.size()) + (m_stop ? tr("  (cancelled)") : QString()));
    m_model->setRows(std::move(rows));
    m_btn->setEnabled(true);
    m_cancel->setEnabled(false);
}

// ================================================================== Columns
ColumnsDialog::ColumnsDialog(QWidget *parent, const QSet<int> &hidden) : QDialog(parent)
{
    setWindowTitle(tr("Select Columns"));
    auto *lay = new QVBoxLayout(this);
    m_list = new QListWidget;
    for (int i = 0; i < ColCount; ++i) {
        auto *it = new QListWidgetItem(QString::fromLatin1(COLUMNS[i].title), m_list);
        it->setData(Qt::UserRole, i);
        it->setCheckState(i == ColName || !hidden.contains(i) ? Qt::Checked : Qt::Unchecked);
        if (i == ColName)
            it->setFlags(it->flags() & ~Qt::ItemIsEnabled);
    }
    lay->addWidget(m_list);
    auto *bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(bb, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, this, &QDialog::reject);
    lay->addWidget(bb);
    resize(300, 540);
}

QSet<int> ColumnsDialog::visibleColumns() const
{
    QSet<int> out;
    for (int r = 0; r < m_list->count(); ++r)
        if (m_list->item(r)->checkState() == Qt::Checked)
            out.insert(m_list->item(r)->data(Qt::UserRole).toInt());
    return out;
}

// ================================================================== Colors
ColorsDialog::ColorsDialog(QWidget *parent, const ColorSet &colors) : QDialog(parent)
{
    setWindowTitle(tr("Color Selection"));
    auto *lay = new QVBoxLayout(this);
    auto *grid = new QGridLayout;
    const ColorSet defs = defaultColors();
    for (int c = 0; c < CatCount; ++c) {
        auto *cb = new QCheckBox(QString::fromLatin1(COLOR_CATS[c].label));
        cb->setChecked(colors[size_t(c)].isValid());
        m_colors[size_t(c)] = colors[size_t(c)].isValid() ? colors[size_t(c)] : defs[size_t(c)];
        auto *btn = new QPushButton(tr("Change…"));
        connect(btn, &QPushButton::clicked, this, [this, c] {
            QColor col = QColorDialog::getColor(m_colors[size_t(c)], this);
            if (col.isValid()) {
                m_colors[size_t(c)] = col;
                paint(c);
            }
        });
        grid->addWidget(cb, c, 0);
        grid->addWidget(btn, c, 1);
        m_boxes << cb;
        m_buttons << btn;
        paint(c);
    }
    lay->addLayout(grid);
    auto *bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel | QDialogButtonBox::RestoreDefaults);
    connect(bb, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(bb->button(QDialogButtonBox::RestoreDefaults), &QPushButton::clicked, this, [this] {
        m_colors = defaultColors();
        for (int c = 0; c < CatCount; ++c) {
            m_boxes[c]->setChecked(true);
            paint(c);
        }
    });
    lay->addWidget(bb);
}

void ColorsDialog::paint(int c)
{
    const QColor &col = m_colors[size_t(c)];
    m_buttons[c]->setStyleSheet(QStringLiteral("background:%1; color:%2;").arg(col.name(), col.lightness() > 110 ? "black" : "white"));
}

ColorSet ColorsDialog::result() const
{
    ColorSet out;
    for (int c = 0; c < CatCount; ++c)
        out[size_t(c)] = m_boxes[c]->isChecked() ? m_colors[size_t(c)] : QColor();
    return out;
}

// ================================================================== Affinity
AffinityDialog::AffinityDialog(QWidget *parent, const QString &name, const QSet<int> &current, int ncpu) : QDialog(parent)
{
    setWindowTitle(tr("Processor Affinity"));
    auto *lay = new QVBoxLayout(this);
    lay->addWidget(new QLabel(tr("Which processors is %1 allowed to run on?").arg(name)));
    auto *grid = new QGridLayout;
    for (int i = 0; i < ncpu; ++i) {
        auto *cb = new QCheckBox(tr("CPU %1").arg(i));
        cb->setChecked(current.contains(i));
        grid->addWidget(cb, i / 4, i % 4);
        m_boxes << cb;
    }
    lay->addLayout(grid);
    auto *bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(bb, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, this, &QDialog::reject);
    lay->addWidget(bb);
}

QVector<int> AffinityDialog::cpus() const
{
    QVector<int> out;
    for (int i = 0; i < m_boxes.size(); ++i)
        if (m_boxes[i]->isChecked())
            out << i;
    return out;
}
