#include "processmodel.h"

#include <QApplication>
#include <QStyle>

#include <algorithm>
#include <ctime>

using namespace pf;

const ColumnDef COLUMNS[ColCount] = {
    {"name", "Process", 260, false, true},
    {"cpu", "CPU", 60, true, true},
    {"private", "Private Bytes", 100, true, true},
    {"ws", "Working Set", 100, true, true},
    {"pid", "PID", 60, true, true},
    {"desc", "Description", 220, false, true},
    {"user", "User Name", 110, false, true},
    {"threads", "Threads", 60, true, false},
    {"handles", "Handles", 60, true, false},
    {"nice", "Priority (Nice)", 60, true, false},
    {"vsize", "Virtual Size", 110, true, false},
    {"cputime", "CPU Time", 90, true, false},
    {"start", "Start Time", 140, false, false},
    {"io_delta", "I/O Delta", 90, true, false},
    {"io_r", "I/O Read Bytes", 110, true, false},
    {"io_w", "I/O Write Bytes", 110, true, false},
    {"status", "Status", 70, false, false},
    {"unit", "Systemd Unit", 200, false, false},
    {"ppid", "Parent PID", 70, true, false},
    {"path", "Image Path", 300, false, false},
    {"cmdline", "Command Line", 400, false, false},
};

const ColorDef COLOR_CATS[CatCount] = {
    {"new", "New Objects", "#46ff46"},
    {"dying", "Deleted Objects", "#ff4646"},
    {"suspended", "Suspended Processes", "#808080"},
    {"flatpak", "Sandboxed Apps (Flatpak)", "#33ccff"},
    {"service", "Services (system.slice)", "#ffd0d0"},
    {"kthread", "Kernel Threads", "#efe4cf"},
    {"own", "Own Processes", "#d0d0ff"},
};

ColorSet defaultColors()
{
    ColorSet c;
    for (int i = 0; i < CatCount; ++i)
        c[size_t(i)] = QColor(QLatin1String(COLOR_CATS[i].def));
    return c;
}

static double monoNow()
{
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return double(ts.tv_sec) + ts.tv_nsec / 1e9;
}

static QString stateName(char s)
{
    switch (s) {
    case 'R': return QStringLiteral("Running");
    case 'S': return QStringLiteral("Sleeping");
    case 'D': return QStringLiteral("Disk Sleep");
    case 'T': case 't': return QStringLiteral("Stopped");
    case 'Z': return QStringLiteral("Zombie");
    case 'I': return QStringLiteral("Idle");
    case 'X': return QStringLiteral("Dead");
    default: return QString(QChar(s));
    }
}

// ------------------------------------------------------------------ Node
void Node::pushHist()
{
    hCpu.push(float(info.cpu));
    hPriv.push(float(std::max<qint64>(0, info.priv)));
    hWs.push(float(std::max<qint64>(0, info.rss)));
    hIo.push(float(info.ioDelta));
}

QString Node::tooltip() const
{
    QStringList t;
    if (!info.cmdline.isEmpty())
        t << QStringLiteral("Command Line:\n    ") + info.cmdline;
    if (!info.exe.isEmpty())
        t << QStringLiteral("Path:\n    ") + info.exe;
    if (!comment.isEmpty())
        t << QStringLiteral("Description:\n    ") + comment;
    if (!info.unit.isEmpty())
        t << QStringLiteral("Systemd Unit:\n    ") + info.unit;
    if (!info.flatpak.isEmpty())
        t << QStringLiteral("Flatpak:\n    ") + info.flatpak;
    return t.isEmpty() ? info.name : t.join('\n');
}

// ------------------------------------------------------------------ Model
ProcessModel::ProcessModel(QObject *parent) : QAbstractItemModel(parent), m_colors(defaultColors())
{
    QStyle *st = QApplication::style();
    m_default = QIcon::fromTheme(QStringLiteral("application-x-executable"), st->standardIcon(QStyle::SP_FileIcon));
    m_kernel = QIcon::fromTheme(QStringLiteral("cpu"), QIcon::fromTheme(QStringLiteral("preferences-system"), m_default));
    m_wine = QIcon::fromTheme(QStringLiteral("wine"), QIcon::fromTheme(QStringLiteral("application-x-ms-dos-executable"), m_default));
}

ProcessModel::~ProcessModel() { qDeleteAll(m_nodes); }

Node *ProcessModel::findPid(int pid) const
{
    for (Node *n : m_nodes)
        if (n->pid == pid && n->state != Node::Dying)
            return n;
    return nullptr;
}

QModelIndex ProcessModel::indexOf(Node *n, int col) const
{
    return n ? createIndex(n->row, col, n) : QModelIndex();
}

int ProcessModel::rowCount(const QModelIndex &parent) const
{
    if (parent.column() > 0)
        return 0;
    return list(parent.isValid() ? static_cast<Node *>(parent.internalPointer()) : nullptr).size();
}

QModelIndex ProcessModel::index(int row, int col, const QModelIndex &parent) const
{
    const auto &l = list(parent.isValid() ? static_cast<Node *>(parent.internalPointer()) : nullptr);
    if (row < 0 || row >= l.size() || col < 0 || col >= ColCount)
        return {};
    return createIndex(row, col, l[row]);
}

QModelIndex ProcessModel::parent(const QModelIndex &idx) const
{
    if (!idx.isValid())
        return {};
    Node *p = static_cast<Node *>(idx.internalPointer())->parent;
    return p ? createIndex(p->row, 0, p) : QModelIndex();
}

QVariant ProcessModel::headerData(int s, Qt::Orientation o, int role) const
{
    if (o != Qt::Horizontal || s < 0 || s >= ColCount)
        return {};
    if (role == Qt::DisplayRole)
        return QString::fromLatin1(COLUMNS[s].title);
    if (role == Qt::TextAlignmentRole && COLUMNS[s].numeric)
        return QVariant::fromValue(Qt::AlignRight | Qt::AlignVCenter);
    return {};
}

QString ProcessModel::display(const Node *n, int col) const
{
    const ProcInfo &i = n->info;
    const bool idle = i.kind == Kind::Idle;
    switch (col) {
    case ColName: return i.name;
    case ColCpu: return fmtCpu(i.cpu);
    case ColPrivate: return fmtK(i.priv);
    case ColWs: return fmtK(i.rss);
    case ColVSize: return fmtK(i.vms);
    case ColPid: return QString::number(i.pid);
    case ColDesc: return n->desc;
    case ColUser: return i.user;
    case ColThreads: return i.threads ? QString::number(i.threads) : QString();
    case ColHandles: return i.fds < 0 ? QString() : num(i.fds);
    case ColNice: return idle ? QString() : QString::number(i.nice);
    case ColCpuTime: return idle ? QString() : fmtTime(i.cputime());
    case ColStart: return idle ? QString() : fmtDateTime(i.ctime);
    case ColIoDelta: return fmtRate(i.ioDelta);
    case ColIoR: return i.ioR < 0 ? QString() : num(i.ioR);
    case ColIoW: return i.ioW < 0 ? QString() : num(i.ioW);
    case ColStatus: return idle ? QString() : stateName(i.state);
    case ColUnit: return i.unit;
    case ColPpid: return i.ppid >= 0 ? QString::number(i.ppid) : QString();
    case ColPath: return i.exe;
    case ColCmdline: return i.cmdline;
    }
    return {};
}

QVariant ProcessModel::sortValue(const Node *n, int col) const
{
    const ProcInfo &i = n->info;
    switch (col) {
    case ColCpu: return i.cpu;
    case ColPrivate: return i.priv;
    case ColWs: return i.rss;
    case ColVSize: return i.vms;
    case ColPid: return i.pid;
    case ColThreads: return i.threads;
    case ColHandles: return i.fds;
    case ColNice: return i.nice;
    case ColCpuTime: return i.cputime();
    case ColStart: return i.ctime;
    case ColIoDelta: return i.ioDelta;
    case ColIoR: return i.ioR;
    case ColIoW: return i.ioW;
    case ColPpid: return i.ppid;
    default: return display(n, col).toLower();
    }
}

QColor ProcessModel::colorOf(const Node *n) const
{
    auto pick = [this](ColorCat c) { return m_colors[size_t(c)]; };
    QColor c;
    if (n->state == Node::Dying && (c = pick(CatDying)).isValid()) return c;
    if (n->state == Node::New && (c = pick(CatNew)).isValid()) return c;
    if (n->info.stopped() && n->info.kind != Kind::Idle && (c = pick(CatSuspended)).isValid()) return c;
    if (n->info.kind == Kind::Flatpak && (c = pick(CatFlatpak)).isValid()) return c;
    if (n->info.kind == Kind::Service && (c = pick(CatService)).isValid()) return c;
    if (n->info.kind == Kind::KThread && (c = pick(CatKThread)).isValid()) return c;
    if (n->info.own && (c = pick(CatOwn)).isValid()) return c;
    return {};
}

QVariant ProcessModel::data(const QModelIndex &idx, int role) const
{
    if (!idx.isValid())
        return {};
    const Node *n = static_cast<Node *>(idx.internalPointer());
    const int col = idx.column();
    switch (role) {
    case Qt::DisplayRole:
        return display(n, col);
    case SortRole:
        return sortValue(n, col);
    case Qt::DecorationRole:
        if (col == ColName)
            return n->icon;
        break;
    case Qt::BackgroundRole:
        if (QColor c = colorOf(n); c.isValid())
            return c;
        break;
    case Qt::ForegroundRole:
        if (QColor c = colorOf(n); c.isValid())
            return QColor(c.lightness() < 110 ? Qt::white : Qt::black);
        break;
    case Qt::TextAlignmentRole:
        if (COLUMNS[col].numeric)
            return QVariant::fromValue(Qt::AlignRight | Qt::AlignVCenter);
        break;
    case Qt::ToolTipRole:
        if (col == ColName || col == ColDesc || col == ColPath || col == ColCmdline)
            return n->tooltip();
        break;
    }
    return {};
}

QIcon ProcessModel::icon(const QString &name)
{
    auto it = m_icons.find(name);
    if (it != m_icons.end())
        return *it;
    QIcon ic = name.startsWith('/') ? QIcon(name) : QIcon::fromTheme(name);
    m_icons.insert(name, ic);
    return ic;
}

void ProcessModel::decorate(Node *n)
{
    const ProcInfo &i = n->info;
    if (i.kind == Kind::Idle) {
        n->icon = m_kernel;
    } else if (i.kind == Kind::KThread) {
        n->icon = m_kernel;
        n->desc = QStringLiteral("Kernel Thread");
    } else {
        QIcon ic;
        if (const auto *e = m_desktop.lookup(i.name, i.exe, i.flatpak)) {
            n->desc = e->name;
            n->comment = e->comment;
            if (!e->icon.isEmpty())
                ic = icon(e->icon);
        }
        if (ic.isNull() && QIcon::hasThemeIcon(i.name.toLower()))
            ic = icon(i.name.toLower());
        if (ic.isNull())
            ic = i.name.endsWith(QLatin1String(".exe"), Qt::CaseInsensitive) ? m_wine : m_default;
        if (n->desc.isEmpty() && i.kind == Kind::Service)
            n->desc = i.unit;
        n->icon = ic;
    }
    n->search = QStringList{i.name, QString::number(i.pid), i.user, n->desc, i.unit, i.cmdline}.join(' ').toLower();
}

Node *ProcessModel::wantParent(Node *n, const QHash<int, Node *> &byPid) const
{
    if (!m_tree)
        return nullptr;
    const int ppid = n->info.ppid;
    if (ppid <= 0 || ppid == n->pid)
        return nullptr;
    Node *p = byPid.value(ppid);
    if (!p || p->info.ctime > n->info.ctime + 1)
        return nullptr;
    for (Node *a = p; a; a = a->parent)
        if (a == n)
            return nullptr;
    return p;
}

void ProcessModel::reindex(QVector<Node *> &l, int from)
{
    for (int i = from; i < l.size(); ++i)
        l[i]->row = i;
}

void ProcessModel::insert(Node *n, Node *parent)
{
    auto &l = list(parent);
    beginInsertRows(indexOf(parent), l.size(), l.size());
    n->parent = parent;
    n->row = l.size();
    l.push_back(n);
    endInsertRows();
}

void ProcessModel::move(Node *n, Node *newParent)
{
    auto &src = list(n->parent);
    auto &dst = list(newParent);
    if (&src == &dst)
        return;
    if (!beginMoveRows(indexOf(n->parent), n->row, n->row, indexOf(newParent), dst.size()))
        return;
    src.removeAt(n->row);
    reindex(src, n->row);
    n->parent = newParent;
    n->row = dst.size();
    dst.push_back(n);
    endMoveRows();
}

void ProcessModel::remove(Node *n)
{
    const auto kids = n->children;
    for (Node *c : kids)
        move(c, n->parent);
    auto &l = list(n->parent);
    const int row = n->row;
    beginRemoveRows(indexOf(n->parent), row, row);
    l.removeAt(row);
    reindex(l, row);
    endRemoveRows();
    m_nodes.remove(n->key);
    delete n;
}

void ProcessModel::emitChanged(bool all)
{
    // Only rows whose values changed are signalled: most processes sleep, so this
    // keeps proxy re-sorting and repaints cheap.
    auto emitFor = [this, all](Node *p) {
        const auto &l = list(p);
        const QModelIndex pi = indexOf(p);
        int first = -1;
        for (int r = 0; r <= l.size(); ++r) {
            const bool d = r < l.size() && (all || l[r]->dirty);
            if (d && first < 0)
                first = r;
            else if (!d && first >= 0) {
                emit dataChanged(index(first, 0, pi), index(r - 1, ColCount - 1, pi));
                first = -1;
            }
            if (r < l.size())
                l[r]->dirty = false;
        }
    };
    emitFor(nullptr);
    for (Node *n : std::as_const(m_nodes))
        if (!n->children.isEmpty())
            emitFor(n);
}

static bool valuesChanged(const ProcInfo &a, const ProcInfo &b)
{
    return a.cpu != b.cpu || a.rss != b.rss || a.priv != b.priv || a.vms != b.vms || a.threads != b.threads
        || a.fds != b.fds || a.nice != b.nice || a.state != b.state || a.ioDelta != b.ioDelta || a.ioR != b.ioR
        || a.ioW != b.ioW || a.utime != b.utime || a.stime != b.stime || a.ppid != b.ppid;
}

void ProcessModel::update(const Snapshot &snap)
{
    const double now = monoNow();
    QHash<quint64, const ProcInfo *> procs;
    procs.reserve(snap.procs.size());
    for (const ProcInfo &p : snap.procs)
        procs.insert(p.key, &p);

    QVector<Node *> expired;
    for (Node *n : std::as_const(m_nodes)) {
        if (!procs.contains(n->key) && n->state != Node::Dying) {
            n->state = Node::Dying;
            n->until = now + highlight;
            n->info.cpu = 0;
            n->info.ioDelta = 0;
            n->dirty = true;
        } else if (n->state == Node::Dying && now >= n->until) {
            expired << n;
        }
    }
    for (Node *n : expired)
        remove(n);

    QHash<int, Node *> byPid;
    byPid.reserve(m_nodes.size() + 16);
    for (Node *n : std::as_const(m_nodes))
        if (n->state != Node::Dying)
            byPid.insert(n->pid, n);

    QVector<const ProcInfo *> fresh;
    for (const ProcInfo &p : snap.procs) {
        if (Node *n = m_nodes.value(p.key)) {
            if (valuesChanged(n->info, p))
                n->dirty = true;
            n->info = p;
            n->pushHist();
            if (n->state == Node::New && now >= n->until) {
                n->state = Node::Normal;
                n->dirty = true;
            }
        } else {
            fresh << &p;
        }
    }
    std::sort(fresh.begin(), fresh.end(), [](auto a, auto b) { return a->start != b->start ? a->start < b->start : a->pid < b->pid; });
    for (const ProcInfo *p : fresh) {
        Node *n = new Node;
        n->key = p->key;
        n->pid = p->pid;
        n->info = *p;
        n->pushHist();
        decorate(n);
        if (m_initialized) {
            n->state = Node::New;
            n->until = now + highlight;
        }
        m_nodes.insert(n->key, n);
        byPid.insert(n->pid, n);
        insert(n, wantParent(n, byPid));
    }
    if (m_tree) {
        const auto all = m_nodes.values();
        for (Node *n : all) {
            if (n->state == Node::Dying)
                continue;
            Node *want = wantParent(n, byPid);
            if (want != n->parent)
                move(n, want);
        }
    }
    m_initialized = true;
    emitChanged(false);
}

void ProcessModel::setTreeMode(bool on)
{
    beginResetModel();
    m_tree = on;
    auto ordered = m_nodes.values();
    std::sort(ordered.begin(), ordered.end(), [](Node *a, Node *b) {
        return a->info.start != b->info.start ? a->info.start < b->info.start : a->pid < b->pid;
    });
    QHash<int, Node *> byPid;
    for (Node *n : ordered) {
        n->children.clear();
        n->parent = nullptr;
        if (n->state != Node::Dying)
            byPid.insert(n->pid, n);
    }
    m_roots.clear();
    for (Node *n : ordered) {
        Node *p = wantParent(n, byPid);
        auto &l = list(p);
        n->parent = p;
        n->row = l.size();
        l.push_back(n);
    }
    endResetModel();
}

void ProcessModel::setColors(const ColorSet &c)
{
    m_colors = c;
    emitChanged(true);
}

// ------------------------------------------------------------------ Proxy
ProcProxy::ProcProxy(QObject *parent) : QSortFilterProxyModel(parent)
{
    setRecursiveFilteringEnabled(true);
    setDynamicSortFilter(true);
    setSortRole(SortRole);
}

void ProcProxy::setText(const QString &t)
{
    beginFilterChange();
    m_text = t.trimmed().toLower();
    endFilterChange(QSortFilterProxyModel::Direction::Rows);
}

void ProcProxy::setHideKThreads(bool on)
{
    beginFilterChange();
    m_hideK = on;
    endFilterChange(QSortFilterProxyModel::Direction::Rows);
}

bool ProcProxy::filterAcceptsRow(int row, const QModelIndex &parent) const
{
    const Node *n = static_cast<Node *>(sourceModel()->index(row, 0, parent).internalPointer());
    if (!n)
        return true;
    if (m_hideK && n->info.kind == Kind::KThread)
        return false;
    return m_text.isEmpty() || n->search.contains(m_text);
}
