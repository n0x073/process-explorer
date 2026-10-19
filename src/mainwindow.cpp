#include "mainwindow.h"
#include "collector.h"
#include "dialogs.h"
#include "sysinfodialog.h"

#include <QAction>
#include <QActionGroup>
#include <QApplication>
#include <QClipboard>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QCloseEvent>
#include <QDesktopServices>
#include <QFileDialog>
#include <QFileInfo>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenuBar>
#include <QMessageBox>
#include <QPainter>
#include <QProcess>
#include <QSortFilterProxyModel>
#include <QSplitter>
#include <QStandardPaths>
#include <QStatusBar>
#include <QSysInfo>
#include <QSystemTrayIcon>
#include <QTableView>
#include <QTimer>
#include <QToolBar>
#include <QTreeView>
#include <QUrl>

#include <csignal>
#include <sched.h>
#include <sys/resource.h>
#include <unistd.h>

using namespace pf;

static const QPair<const char *, int> PRIORITIES[] = {
    {"Realtime (-20)", -20}, {"High (-10)", -10}, {"Above Normal (-5)", -5},
    {"Normal (0)", 0}, {"Below Normal (5)", 5}, {"Idle (19)", 19}};
static const int SPEEDS[] = {500, 1000, 2000, 5000, 10000};

static QIcon appIcon()
{
    return QIcon::fromTheme(QStringLiteral("utilities-system-monitor"), QIcon::fromTheme(QStringLiteral("system-monitor")));
}

MainWindow::MainWindow()
    : m_settings(QStringLiteral("procexp-linux"), QStringLiteral("procexp")),
      m_history(std::max(1, int(sysconf(_SC_NPROCESSORS_ONLN))))
{
    m_interval = m_settings.value("interval", 1000).toInt();
    m_confirmKill = m_settings.value("confirmKill", true).toBool();
    m_lowerMode = m_settings.value("lowerMode", "handles").toString() == QLatin1String("dlls") ? LowerDlls : LowerHandles;

    QString user = userName(getuid());
    setWindowTitle(QStringLiteral("Process Explorer - Linux [%1\\%2]%3")
                       .arg(QSysInfo::machineHostName(), user, geteuid() == 0 ? QStringLiteral(" (Administrator)") : QString()));
    setWindowIcon(appIcon());

    m_model = new ProcessModel(this);
    ColorSet colors = defaultColors();
    for (int c = 0; c < CatCount; ++c) {
        QString v = m_settings.value(QStringLiteral("colors/") + COLOR_CATS[c].id, COLOR_CATS[c].def).toString();
        colors[size_t(c)] = v == QLatin1String("none") ? QColor() : QColor(v);
    }
    m_model->setColors(colors);
    m_model->highlight = m_settings.value("highlight", 2.0).toDouble();
    m_model->setTreeMode(m_settings.value("treeMode", true).toBool());
    m_proxy = new ProcProxy(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setHideKThreads(m_settings.value("hideKthreads", false).toBool());

    buildTree();
    buildLower();
    m_split = new QSplitter(Qt::Vertical);
    m_split->addWidget(m_tree);
    m_split->addWidget(m_lower);
    m_split->setStretchFactor(0, 3);
    m_split->setStretchFactor(1, 1);
    setCentralWidget(m_split);
    buildActions();
    buildMenus();
    buildToolbar();
    buildStatus();

    if (!restoreGeometry(m_settings.value("geometry").toByteArray()))
        resize(1150, 760);
    m_split->restoreState(m_settings.value("splitter").toByteArray());
    m_lower->setVisible(m_settings.value("lowerPane", false).toBool());
    aLower->setChecked(m_lower->isVisible());
    setLowerMode(m_lowerMode);
    aOnTop->setChecked(m_settings.value("onTop", false).toBool());
    aTray->setChecked(m_settings.value("tray", false).toBool());

    m_collector = new Collector;
    m_collector->moveToThread(&m_thread);
    connect(&m_thread, &QThread::finished, m_collector, &QObject::deleteLater);
    connect(this, &MainWindow::requestCollect, m_collector, &Collector::collect);
    connect(m_collector, &Collector::ready, this, &MainWindow::onSnapshot);
    m_thread.start(QThread::LowPriority);
    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &MainWindow::request);
    m_timer->start(m_interval);
    request();
}

MainWindow::~MainWindow()
{
    m_thread.quit();
    m_thread.wait(3000);
}

// ================================================================== UI construction
void MainWindow::buildTree()
{
    m_tree = new QTreeView;
    m_tree->setModel(m_proxy);
    m_tree->setUniformRowHeights(true);
    m_tree->setAllColumnsShowFocus(true);
    m_tree->setAnimated(false);
    m_tree->setIndentation(14);
    m_tree->setSortingEnabled(true);
    m_tree->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_tree, &QTreeView::customContextMenuRequested, this, [this](const QPoint &pos) {
        if (!m_tree->indexAt(pos).isValid())
            return;
        QMenu m(this);
        fillProcessMenu(&m);
        m.exec(m_tree->viewport()->mapToGlobal(pos));
    });
    connect(m_tree, &QTreeView::doubleClicked, this, [this] { showProperties(); });
    QHeaderView *h = m_tree->header();
    h->setSectionsMovable(true);
    h->setStretchLastSection(false);
    for (int i = 0; i < ColCount; ++i) {
        h->resizeSection(i, COLUMNS[i].width);
        h->setSectionHidden(i, !COLUMNS[i].visible);
    }
    h->restoreState(m_settings.value("header").toByteArray());
    h->setSortIndicator(-1, Qt::AscendingOrder);
    m_proxy->sort(-1);
    connect(h, &QHeaderView::sectionClicked, this, &MainWindow::headerClicked);
    connect(m_proxy, &QAbstractItemModel::rowsInserted, this, [this](const QModelIndex &parent, int first, int last) {
        if (!m_initialDone)
            return;
        for (int r = first; r <= last; ++r)
            m_tree->expand(m_proxy->index(r, 0, parent));
    });
    connect(m_tree->selectionModel(), &QItemSelectionModel::currentChanged, this, [this] { refreshLower(); });
}

void MainWindow::buildLower()
{
    m_handleModel = new ListModel({"Type", "Name", "FD"}, this);
    m_handleModel->setNumeric({2});
    m_dllModel = new ListModel({"Name", "Path", "Base", "Size", "Mapping"}, this);
    m_dllModel->setNumeric({3});
    m_dllModel->setFormatter(2, [](const QVariant &v) { return QStringLiteral("0x%1").arg(v.toULongLong(), 0, 16).toUpper().replace("0X", "0x"); });
    m_dllModel->setFormatter(3, [](const QVariant &v) { return fmtK(v.toLongLong()); });
    m_lowerProxy = new QSortFilterProxyModel(this);
    m_lowerProxy->setSortRole(SortRole);
    m_lower = new QTableView;
    m_lower->setModel(m_lowerProxy);
    m_lower->setSortingEnabled(true);
    m_lower->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_lower->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_lower->verticalHeader()->hide();
    m_lower->verticalHeader()->setDefaultSectionSize(20);
    m_lower->setWordWrap(false);
    m_lower->horizontalHeader()->setStretchLastSection(true);
}

QAction *MainWindow::act(const QString &text, const QString &shortcut, const QString &icon, bool checkable)
{
    auto *a = new QAction(text, this);
    if (!icon.isEmpty())
        a->setIcon(QIcon::fromTheme(icon));
    if (!shortcut.isEmpty()) {
        a->setShortcut(QKeySequence(shortcut));
        addAction(a);
    }
    a->setCheckable(checkable);
    return a;
}

void MainWindow::buildActions()
{
    aRun = act(tr("&Run…"), "Ctrl+R", "system-run");
    connect(aRun, &QAction::triggered, this, [this] { runProgram(false); });
    aRunAdm = act(tr("Run as &Administrator…"));
    connect(aRunAdm, &QAction::triggered, this, [this] { runProgram(true); });
    aSave = act(tr("&Save"), "Ctrl+S", "document-save");
    connect(aSave, &QAction::triggered, this, [this] { save(false); });
    aSaveAs = act(tr("Save &As…"), "Ctrl+Shift+S", "document-save-as");
    connect(aSaveAs, &QAction::triggered, this, [this] { save(true); });
    aExit = act(tr("E&xit"), "Ctrl+Q", "application-exit");
    connect(aExit, &QAction::triggered, this, &QWidget::close);

    aOnTop = act(tr("&Always On Top"), {}, {}, true);
    connect(aOnTop, &QAction::toggled, this, [this](bool on) { setWindowFlag(Qt::WindowStaysOnTopHint, on); show(); });
    aConfirm = act(tr("&Confirm Kill"), {}, {}, true);
    aConfirm->setChecked(m_confirmKill);
    connect(aConfirm, &QAction::toggled, this, [this](bool on) { m_confirmKill = on; });
    aTray = act(tr("Show CPU &Tray Icon"), {}, {}, true);
    connect(aTray, &QAction::toggled, this, &MainWindow::setTray);
    aHighlight = act(tr("&Difference Highlight Duration…"));
    connect(aHighlight, &QAction::triggered, this, [this] {
        bool ok;
        double v = QInputDialog::getDouble(this, tr("Difference Highlight Duration"),
                                           tr("Highlight new and deleted processes for (seconds):"), m_model->highlight, 0, 30, 1, &ok);
        if (ok)
            m_model->highlight = v;
    });
    aColors = act(tr("Configure Co&lors…"));
    connect(aColors, &QAction::triggered, this, &MainWindow::configureColors);

    aSysInfo = act(tr("System &Information…"), "Ctrl+I", "view-statistics");
    connect(aSysInfo, &QAction::triggered, this, &MainWindow::showSysInfo);
    aTreeMode = act(tr("Show Process &Tree"), "Ctrl+T", "view-list-tree", true);
    aTreeMode->setChecked(m_model->treeMode());
    connect(aTreeMode, &QAction::toggled, this, [this](bool on) {
        m_tree->header()->setSortIndicator(-1, Qt::AscendingOrder);
        m_proxy->sort(-1);
        m_model->setTreeMode(on);
        expandInitial();
    });
    aKThreads = act(tr("Hide &Kernel Threads"), {}, {}, true);
    aKThreads->setChecked(m_proxy->hideKThreads());
    connect(aKThreads, &QAction::toggled, m_proxy, &ProcProxy::setHideKThreads);
    aLower = act(tr("Show &Lower Pane"), "Ctrl+L", "view-split-top-bottom", true);
    connect(aLower, &QAction::toggled, this, [this](bool on) { m_lower->setVisible(on); refreshLower(); });
    auto *lg = new QActionGroup(this);
    aHandles = act(tr("&Handles (Open Files)"), "Ctrl+H", "document-open-folder", true);
    aDlls = act(tr("&DLLs (Mapped Libraries)"), "Ctrl+D", "application-x-sharedlib", true);
    lg->addAction(aHandles);
    lg->addAction(aDlls);
    connect(aHandles, &QAction::triggered, this, [this] { setLowerMode(LowerHandles, true); });
    connect(aDlls, &QAction::triggered, this, [this] { setLowerMode(LowerDlls, true); });
    aRefresh = act(tr("&Refresh Now"), "F5", "view-refresh");
    connect(aRefresh, &QAction::triggered, this, &MainWindow::request);
    aPause = act(tr("&Paused"), "Space", "media-playback-pause", true);
    connect(aPause, &QAction::toggled, this, &MainWindow::setPaused);
    aColumns = act(tr("Select &Columns…"), {}, "view-choose");
    connect(aColumns, &QAction::triggered, this, &MainWindow::selectColumns);
    auto *sg = new QActionGroup(this);
    for (int ms : SPEEDS) {
        QAction *a = act(tr("%1 seconds").arg(ms / 1000.0), {}, {}, true);
        a->setChecked(ms == m_interval);
        sg->addAction(a);
        connect(a, &QAction::triggered, this, [this, ms] { setSpeed(ms); });
        m_speedActs << a;
    }

    aProps = act(tr("&Properties…"), "Return", "document-properties");
    connect(aProps, &QAction::triggered, this, &MainWindow::showProperties);
    aKill = act(tr("&Kill Process"), "Delete", "process-stop");
    connect(aKill, &QAction::triggered, this, [this] { killSelected(false, SIGKILL); });
    aKillTree = act(tr("Kill Process &Tree"), "Shift+Delete");
    connect(aKillTree, &QAction::triggered, this, [this] { killSelected(true, SIGKILL); });
    aTerm = act(tr("&Terminate Process (SIGTERM)"), "Ctrl+Delete");
    connect(aTerm, &QAction::triggered, this, [this] { killSelected(false, SIGTERM); });
    aRestart = act(tr("Re&start"));
    connect(aRestart, &QAction::triggered, this, &MainWindow::restartSelected);
    aSuspend = act(tr("&Suspend"));
    connect(aSuspend, &QAction::triggered, this, &MainWindow::toggleSuspendSelected);
    aAffinity = act(tr("Set &Affinity…"));
    connect(aAffinity, &QAction::triggered, this, &MainWindow::setAffinity);
    aOpenLoc = act(tr("&Open File Location"), {}, "folder-open");
    connect(aOpenLoc, &QAction::triggered, this, [this] {
        if (Node *n = aliveSelected(); n && !n->info.exe.isEmpty())
            QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(n->info.exe).path()));
    });
    aSearch = act(tr("Search &Online…"), "Ctrl+M", "internet-web-browser");
    connect(aSearch, &QAction::triggered, this, [this] {
        if (Node *n = aliveSelected())
            QDesktopServices::openUrl(QUrl(QStringLiteral("https://www.google.com/search?q=") +
                                           QUrl::toPercentEncoding(n->info.name + QStringLiteral(" linux process"))));
    });
    aCopy = act(tr("&Copy"), "Ctrl+C", "edit-copy");
    connect(aCopy, &QAction::triggered, this, &MainWindow::copySelected);
    aFind = act(tr("Find Handle or &DLL…"), "Ctrl+F", "edit-find");
    connect(aFind, &QAction::triggered, this, &MainWindow::showFind);
    aFindWindow = act(tr("Find &Window's Process"), {}, "crosshairs");
    aFindWindow->setToolTip(tr("Find Window's Process (click on a window)"));
    connect(aFindWindow, &QAction::triggered, this, &MainWindow::findWindowProcess);
    aFilter = act(tr("&Filter…"), "Ctrl+K", "view-filter");
    connect(aFilter, &QAction::triggered, this, [this] { m_filter->setFocus(); m_filter->selectAll(); });
    aAbout = act(tr("&About"), {}, "help-about");
    connect(aAbout, &QAction::triggered, this, [this] {
        QMessageBox::about(this, tr("About Process Explorer for Linux"),
                           tr("<b>Process Explorer for Linux</b><br><br>A native Qt6/C++ re-implementation of the "
                              "Sysinternals Process Explorer UI for Linux.<br><br>"
                              "Handles = open file descriptors<br>DLLs = mapped shared objects<br>"
                              "Services = systemd system units<br>Sandboxed apps = Flatpak"));
    });

    m_prioMenu = new QMenu(tr("Set &Priority"), this);
    auto *pg = new QActionGroup(this);
    for (const auto &[label, val] : PRIORITIES) {
        QAction *a = m_prioMenu->addAction(tr(label));
        a->setCheckable(true);
        pg->addAction(a);
        const int v = val;
        connect(a, &QAction::triggered, this, [this, v] { setPriority(v); });
        m_prioActs.insert(val, a);
    }
}

void MainWindow::fillProcessMenu(QMenu *m)
{
    Node *n = selectedNode();
    const bool alive = n && n->pid > 0 && n->state != Node::Dying;
    aSuspend->setText(alive && n->info.stopped() ? tr("&Resume") : tr("&Suspend"));
    for (QAction *a : std::as_const(m_prioActs))
        a->setChecked(false);
    if (alive && m_prioActs.contains(n->info.nice))
        m_prioActs[n->info.nice]->setChecked(true);
    m->addMenu(m_prioMenu);
    m_prioMenu->setEnabled(alive);
    for (QAction *a : {aAffinity, (QAction *)nullptr, aTerm, aKill, aKillTree, aRestart, aSuspend, (QAction *)nullptr,
                       aOpenLoc, aSearch, (QAction *)nullptr, aCopy, aProps}) {
        if (!a)
            m->addSeparator();
        else
            m->addAction(a);
    }
    for (QAction *a : {aAffinity, aTerm, aKill, aKillTree, aRestart, aSuspend, aOpenLoc, aSearch, aProps})
        a->setEnabled(alive);
}

void MainWindow::buildMenus()
{
    QMenuBar *mb = menuBar();
    QMenu *m = mb->addMenu(tr("&File"));
    m->addActions({aRun, aRunAdm});
    m->addSeparator();
    m->addActions({aSave, aSaveAs});
    m->addSeparator();
    m->addAction(aExit);

    m = mb->addMenu(tr("&Options"));
    m->addActions({aOnTop, aConfirm, aTray});
    m->addSeparator();
    m->addActions({aHighlight, aColors});

    m = mb->addMenu(tr("&View"));
    m->addAction(aSysInfo);
    m->addSeparator();
    m->addActions({aTreeMode, aKThreads, aLower});
    QMenu *lp = m->addMenu(tr("Lower Pane &View"));
    lp->addActions({aHandles, aDlls});
    m->addSeparator();
    m->addAction(aRefresh);
    QMenu *sp = m->addMenu(tr("&Update Speed"));
    sp->addActions(m_speedActs);
    sp->addSeparator();
    sp->addAction(aPause);
    m->addSeparator();
    m->addAction(aColumns);

    QMenu *pm = mb->addMenu(tr("&Process"));
    connect(pm, &QMenu::aboutToShow, this, [this, pm] { pm->clear(); fillProcessMenu(pm); });

    m = mb->addMenu(tr("Fi&nd"));
    m->addActions({aFind, aFindWindow, aFilter, aSearch});

    QMenu *um = mb->addMenu(tr("&Users"));
    connect(um, &QMenu::aboutToShow, this, [this, um] {
        um->clear();
        QSet<QString> users;
        for (Node *n : m_model->nodes())
            if (!n->info.user.isEmpty())
                users.insert(n->info.user);
        QStringList sorted(users.begin(), users.end());
        sorted.sort();
        for (const QString &u : sorted)
            um->addAction(u, this, [this, u] { m_filter->setText(u); });
        um->addSeparator();
        um->addAction(tr("Show All"), this, [this] { m_filter->clear(); });
    });

    m = mb->addMenu(tr("&Help"));
    m->addAction(aAbout);
}

void MainWindow::buildToolbar()
{
    QToolBar *tb = addToolBar(tr("Main"));
    tb->setObjectName("main_toolbar");
    tb->setMovable(false);
    tb->addAction(aSave);
    tb->addSeparator();
    tb->addActions({aRefresh, aSysInfo, aTreeMode});
    tb->addSeparator();
    tb->addActions({aProps, aKill});
    tb->addSeparator();
    tb->addActions({aFind, aFindWindow, aLower, aDlls, aHandles});
    tb->addSeparator();

    SysHistory *h = &m_history;
    struct D { const char *name, *tip; std::vector<std::tuple<const FRing *, QColor, bool>> series; double max; };
    std::vector<D> defs = {
        {"CPU", "cpu", {{&h->cpu, pal::Cpu, true}, {&h->kern, pal::Kernel, true}}, 100},
        {"Commit", "commit", {{&h->commit, pal::Commit, true}}, 100},
        {"Physical", "phys", {{&h->phys, pal::Phys, true}}, 100},
        {"I/O", "io", {{&h->diskT, pal::Read, true}, {&h->diskW, pal::Write, false}}, 0},
    };
    if (!findGpu().isEmpty())
        defs.push_back({"GPU", "gpu", {{&h->gpu, pal::Gpu, true}}, 100});
    for (const D &d : defs) {
        auto *g = new Graph(d.max, {}, 24);
        for (const auto &[r, c, fill] : d.series)
            g->addSeries(r, c, fill);
        g->setFixedSize(96, 26);
        const QString kind = QLatin1String(d.tip);
        g->tooltipFn = [h, kind](int b) { return h->tip(kind, b); };
        connect(g, &Graph::clicked, this, &MainWindow::showSysInfo);
        tb->addWidget(g);
        auto *gap = new QWidget;
        gap->setFixedWidth(4);
        tb->addWidget(gap);
        m_tbGraphs << g;
    }
    auto *spacer = new QWidget;
    spacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    tb->addWidget(spacer);
    m_filter = new QLineEdit;
    m_filter->setPlaceholderText(tr("Filter (Ctrl+K)"));
    m_filter->setClearButtonEnabled(true);
    m_filter->setFixedWidth(220);
    connect(m_filter, &QLineEdit::textChanged, this, [this](const QString &t) {
        m_proxy->setText(t);
        if (!t.isEmpty())
            m_tree->expandAll();
    });
    tb->addWidget(m_filter);
}

void MainWindow::buildStatus()
{
    QStatusBar *sb = statusBar();
    for (QLabel **l : {&m_stCpu, &m_stCommit, &m_stProcs, &m_stPhys}) {
        *l = new QLabel;
        (*l)->setContentsMargins(6, 0, 12, 0);
        sb->addWidget(*l);
    }
    m_stPaused = new QLabel;
    sb->addPermanentWidget(m_stPaused);
}

// ================================================================== refresh cycle
void MainWindow::request()
{
    if (m_pending)
        return;
    m_pending = true;
    emit requestCollect();
}

void MainWindow::onSnapshot(SnapshotPtr snap)
{
    m_pending = false;
    if (!snap)
        return;
    m_history.add(*snap);
    m_model->update(*snap);
    if (!m_initialDone) {
        m_initialDone = true;
        expandInitial();
    }
    const SysInfo &s = snap->sys;
    m_stCpu->setText(tr("CPU Usage: %1%").arg(fdec(s.cpu)));
    m_stCommit->setText(tr("Commit Charge: %1%").arg(fdec(s.commitPct)));
    m_stProcs->setText(tr("Processes: %1").arg(s.processes));
    m_stPhys->setText(tr("Physical Usage: %1%").arg(fdec(s.physPct)));
    for (Graph *g : std::as_const(m_tbGraphs))
        g->advance();
    refreshLower();
    updateTray();
    if (m_sysinfo)
        m_sysinfo->refresh();
    emit ticked();
}

void MainWindow::expandInitial()
{
    m_tree->expandAll();
    if (Node *kt = m_model->findPid(2)) {
        QModelIndex idx = m_proxy->mapFromSource(m_model->indexOf(kt));
        if (idx.isValid())
            m_tree->collapse(idx);
    }
}

void MainWindow::headerClicked(int col)
{
    m_sortClicks = col == m_sortCol ? m_sortClicks + 1 : 1;
    m_sortCol = col;
    QHeaderView *h = m_tree->header();
    if (m_sortClicks == 1 && COLUMNS[col].numeric) {
        h->setSortIndicator(col, Qt::DescendingOrder);
    } else if (m_sortClicks >= 3) { // third click: back to tree order like Process Explorer
        h->setSortIndicator(-1, Qt::AscendingOrder);
        m_proxy->sort(-1);
        m_sortCol = -1;
        m_sortClicks = 0;
    }
}

// ================================================================== lower pane
void MainWindow::setLowerMode(LowerMode mode, bool show)
{
    m_lowerMode = mode;
    aHandles->setChecked(mode == LowerHandles);
    aDlls->setChecked(mode == LowerDlls);
    m_lowerProxy->setSourceModel(mode == LowerHandles ? m_handleModel : m_dllModel);
    const QVector<int> widths = mode == LowerHandles ? QVector<int>{110, 600, 60} : QVector<int>{200, 450, 130, 90, 90};
    for (int i = 0; i < widths.size(); ++i)
        m_lower->setColumnWidth(i, widths[i]);
    if (show && !m_lower->isVisible())
        aLower->setChecked(true);
    refreshLower();
}

void MainWindow::refreshLower()
{
    if (!m_lower->isVisible())
        return;
    Node *n = selectedNode();
    if (!n || n->pid <= 0) {
        m_handleModel->setRows({});
        m_dllModel->setRows({});
        return;
    }
    QVector<ListModel::Row> rows;
    if (m_lowerMode == LowerHandles) {
        const auto sockets = socketMap(n->pid);
        auto hs = readHandles(n->pid, &sockets);
        std::sort(hs.begin(), hs.end(), [](const HandleRow &a, const HandleRow &b) { return a.fd < b.fd; });
        for (const HandleRow &h : hs)
            rows.push_back({h.type, h.name, h.fd});
        m_handleModel->setRows(std::move(rows));
    } else {
        for (const MapRow &m : readMaps(n->pid))
            rows.push_back({m.name, m.path, m.base, qint64(m.size), m.mapping});
        m_dllModel->setRows(std::move(rows));
    }
}

// ================================================================== selection
Node *MainWindow::selectedNode() const
{
    QModelIndex idx = m_tree->currentIndex();
    if (!idx.isValid())
        return nullptr;
    return static_cast<Node *>(m_proxy->mapToSource(idx).internalPointer());
}

Node *MainWindow::aliveSelected() const
{
    Node *n = selectedNode();
    return n && n->pid > 0 && n->state != Node::Dying ? n : nullptr;
}

void MainWindow::selectPid(int pid, LowerMode lower, bool showLower)
{
    Node *n = m_model->findPid(pid);
    if (!n) {
        QMessageBox::information(this, tr("Process Explorer"), tr("Process %1 no longer exists.").arg(pid));
        return;
    }
    QModelIndex idx = m_proxy->mapFromSource(m_model->indexOf(n));
    if (!idx.isValid()) {
        m_filter->clear();
        if (m_proxy->hideKThreads())
            aKThreads->setChecked(false);
        idx = m_proxy->mapFromSource(m_model->indexOf(n));
    }
    for (QModelIndex p = idx.parent(); p.isValid(); p = p.parent())
        m_tree->expand(p);
    m_tree->setCurrentIndex(idx);
    m_tree->scrollTo(idx, QAbstractItemView::PositionAtCenter);
    setLowerMode(lower, showLower);
    raise();
    activateWindow();
}

QVector<int> MainWindow::visibleColumns() const
{
    QVector<int> cols;
    QHeaderView *h = m_tree->header();
    for (int v = 0; v < h->count(); ++v) {
        int l = h->logicalIndex(v);
        if (!h->isSectionHidden(l))
            cols << l;
    }
    return cols;
}

// ================================================================== process actions
void MainWindow::elevate(const QString &program, const QStringList &args, const QString &err)
{
    QString path = program.startsWith('/') ? program : QStandardPaths::findExecutable(program);
    if (!QStandardPaths::findExecutable("pkexec").isEmpty() && !path.isEmpty()) {
        if (QMessageBox::question(this, tr("Process Explorer"), err + tr("\n\nRetry with administrator rights (pkexec)?"))
            == QMessageBox::Yes) {
            QProcess::startDetached(QStringLiteral("pkexec"), QStringList{path} + args);
            QTimer::singleShot(1500, this, &MainWindow::request);
        }
    } else {
        QMessageBox::warning(this, tr("Process Explorer"), err);
    }
}

void MainWindow::signalProcesses(const QVector<quint64> &keys, int sig, const QString &what)
{
    QStringList denied;
    for (quint64 key : keys) {
        int e = signalProcess(keyPid(key), keyStart(key), sig);
        if (e == EPERM)
            denied << QStringLiteral("%1:%2").arg(keyPid(key)).arg(keyStart(key));
    }
    // Elevated retry runs our own binary in helper mode, which re-verifies each
    // process with a pidfd (no plain "kill PID" after a slow password prompt).
    if (!denied.isEmpty())
        elevate(QCoreApplication::applicationFilePath(), QStringList{"--signal", QString::number(sig)} + denied,
                tr("Error %1:\nAccess is denied.").arg(what));
    QTimer::singleShot(300, this, &MainWindow::request);
}

static void collectDescendants(const ProcessModel *m, int pid, QVector<quint64> &out)
{
    for (Node *n : m->nodes())
        if (n->info.ppid == pid && n->pid > 0 && n->state != Node::Dying && !out.contains(n->key)) {
            collectDescendants(m, n->pid, out);
            out << n->key;
        }
}

void MainWindow::killProcess(quint64 key, const QString &name, bool tree, int sig)
{
    if (m_confirmKill) {
        QString verb = sig == SIGTERM ? tr("terminate (SIGTERM)") : tr("kill");
        if (QMessageBox::question(this, tr("Process Explorer"),
                                  tr("Are you sure you want to %1 %2%3?").arg(verb, name, tree ? tr(" and all of its descendants") : QString()))
            != QMessageBox::Yes)
            return;
    }
    QVector<quint64> keys;
    if (tree)
        collectDescendants(m_model, keyPid(key), keys); // children first
    keys << key;
    signalProcesses(keys, sig, tr("killing %1").arg(name));
}

void MainWindow::killSelected(bool tree, int sig)
{
    if (Node *n = aliveSelected())
        killProcess(n->key, n->info.name, tree, sig);
}

void MainWindow::suspendProcess(quint64 key, bool suspend)
{
    signalProcesses({key}, suspend ? SIGSTOP : SIGCONT, suspend ? tr("suspending process") : tr("resuming process"));
}

void MainWindow::toggleSuspendSelected()
{
    if (Node *n = aliveSelected())
        suspendProcess(n->key, !n->info.stopped());
}

void MainWindow::restartSelected()
{
    Node *n = aliveSelected();
    if (!n)
        return;
    const int pid = n->pid;
    const QString name = n->info.name;
    // Pin the process first; everything below reads/acts on exactly this one.
    int pidfd = openPidfd(pid, n->info.start);
    if (pidfd < 0) {
        QMessageBox::warning(this, tr("Process Explorer"), tr("%1 no longer exists.").arg(name));
        return;
    }
    QStringList args = cmdlineArgs(pid);
    QString cwd = readLink(QStringLiteral("/proc/%1/cwd").arg(pid));
    QByteArray env = readFile(QStringLiteral("/proc/%1/environ").arg(pid));
    if (args.isEmpty()) {
        ::close(pidfd);
        QMessageBox::warning(this, tr("Process Explorer"), tr("Unable to restart %1: command line not accessible.").arg(name));
        return;
    }
    if (m_confirmKill && QMessageBox::question(this, tr("Process Explorer"), tr("Are you sure you want to restart %1?").arg(name)) != QMessageBox::Yes) {
        ::close(pidfd);
        return;
    }
    if (int e = sendSignal(pidfd, SIGTERM); e && e != ESRCH) {
        ::close(pidfd);
        QMessageBox::warning(this, tr("Process Explorer"), tr("Error terminating %1: %2").arg(name, QString::fromLocal8Bit(strerror(e))));
        return;
    }
    QApplication::setOverrideCursor(Qt::WaitCursor);
    if (!waitExit(pidfd, 3000)) {
        sendSignal(pidfd, SIGKILL);
        waitExit(pidfd, 1000);
    }
    QApplication::restoreOverrideCursor();
    ::close(pidfd);
    QProcess p;
    p.setProgram(args.takeFirst());
    p.setArguments(args);
    p.setWorkingDirectory(cwd);
    QProcessEnvironment pe;
    for (const QByteArray &e : env.split('\0')) {
        int eq = e.indexOf('=');
        if (eq > 0)
            pe.insert(QString::fromLocal8Bit(e.left(eq)), QString::fromLocal8Bit(e.mid(eq + 1)));
    }
    p.setProcessEnvironment(pe);
    p.setStandardInputFile(QProcess::nullDevice());
    p.setStandardOutputFile(QProcess::nullDevice());
    p.setStandardErrorFile(QProcess::nullDevice());
    if (!p.startDetached())
        QMessageBox::warning(this, tr("Process Explorer"), tr("Error starting %1: %2").arg(name, p.errorString()));
    request();
}

void MainWindow::setPriority(int nice)
{
    Node *n = aliveSelected();
    if (!n)
        return;
    // nice is per thread on Linux -> apply to every thread like Windows does per process
    QStringList denied;
    for (int tid : threadIds(n->pid))
        if (setpriority(PRIO_PROCESS, id_t(tid), nice) != 0 && (errno == EPERM || errno == EACCES))
            denied << QString::number(tid);
    if (!denied.isEmpty())
        elevate("renice", QStringList{"-n", QString::number(nice), "-p"} + denied,
                tr("Error setting priority of %1:\nAccess is denied.").arg(n->info.name));
    request();
}

void MainWindow::setAffinity()
{
    Node *n = aliveSelected();
    if (!n)
        return;
    const int ncpu = std::max(1, int(sysconf(_SC_NPROCESSORS_CONF)));
    cpu_set_t set;
    CPU_ZERO(&set);
    if (sched_getaffinity(n->pid, sizeof set, &set) != 0) {
        QMessageBox::warning(this, tr("Process Explorer"), QString::fromLocal8Bit(strerror(errno)));
        return;
    }
    QSet<int> cur;
    for (int i = 0; i < ncpu; ++i)
        if (CPU_ISSET(i, &set))
            cur.insert(i);
    AffinityDialog d(this, n->info.name, cur, ncpu);
    if (d.exec() != QDialog::Accepted || d.cpus().isEmpty())
        return;
    CPU_ZERO(&set);
    QStringList list;
    for (int c : d.cpus()) {
        CPU_SET(c, &set);
        list << QString::number(c);
    }
    bool denied = false;
    for (int tid : threadIds(n->pid))
        if (sched_setaffinity(tid, sizeof set, &set) != 0 && errno == EPERM)
            denied = true;
    if (denied)
        elevate("taskset", {"-a", "-p", "-c", list.join(','), QString::number(n->pid)}, tr("Error setting affinity:\nAccess is denied."));
}

void MainWindow::showProperties()
{
    Node *n = selectedNode();
    if (!n || n->pid <= 0)
        return;
    (new PropertiesDialog(this, n))->show();
}

void MainWindow::showSysInfo()
{
    if (!m_sysinfo)
        m_sysinfo = new SystemInfoDialog(&m_history, this);
    m_sysinfo->show();
    m_sysinfo->raise();
}

void MainWindow::showFind()
{
    if (!m_find)
        m_find = new FindDialog(this);
    m_find->show();
    m_find->raise();
    m_find->focusEdit();
}

// Wayland lets no client inspect other windows, so Process Explorer's crosshair
// cannot be done directly. KWin offers the same interactive picker it uses for
// "Detect Window Properties": the cursor turns into a crosshair, the user clicks a
// window and KWin returns its properties including the pid.
void MainWindow::findWindowProcess()
{
    QDBusMessage msg = QDBusMessage::createMethodCall(QStringLiteral("org.kde.KWin"), QStringLiteral("/KWin"),
                                                      QStringLiteral("org.kde.KWin"), QStringLiteral("queryWindowInfo"));
    auto *watcher = new QDBusPendingCallWatcher(QDBusConnection::sessionBus().asyncCall(msg, 120000), this);
    aFindWindow->setEnabled(false);
    statusBar()->showMessage(tr("Click on a window to select its process (Esc cancels)…"));
    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this](QDBusPendingCallWatcher *w) {
        w->deleteLater();
        aFindWindow->setEnabled(true);
        statusBar()->clearMessage();
        QDBusPendingReply<QVariantMap> reply = *w;
        if (reply.isError()) {
            const QDBusError e = reply.error();
            if (e.name().contains(QLatin1String("Cancel"), Qt::CaseInsensitive))
                return;
            QString why = e.type() == QDBusError::ServiceUnknown
                ? tr("This feature needs the KDE Plasma window manager (KWin).")
                : e.message();
            QMessageBox::information(this, tr("Find Window's Process"), why);
            return;
        }
        const int pid = reply.value().value(QStringLiteral("pid")).toInt();
        if (pid > 0)
            selectPid(pid, m_lowerMode, false);
    });
}

void MainWindow::copySelected()
{
    Node *n = selectedNode();
    if (!n)
        return;
    QStringList vals;
    for (int c : visibleColumns())
        vals << m_model->display(n, c);
    QApplication::clipboard()->setText(vals.join('\t'));
}

void MainWindow::save(bool ask)
{
    if (ask || m_savePath.isEmpty()) {
        QString fn = QFileDialog::getSaveFileName(this, tr("Save Process Explorer Data"), "Procexp.txt",
                                                  tr("Text files (*.txt);;All files (*)"));
        if (fn.isEmpty())
            return;
        m_savePath = fn;
    }
    const QVector<int> cols = visibleColumns();
    QStringList lines, hdr;
    for (int c : cols)
        hdr << QString::fromLatin1(COLUMNS[c].title);
    lines << hdr.join('\t');
    std::function<void(const QModelIndex &, int)> walk = [&](const QModelIndex &parent, int depth) {
        for (int r = 0; r < m_proxy->rowCount(parent); ++r) {
            QStringList v;
            for (int c : cols)
                v << m_proxy->index(r, c, parent).data().toString();
            v[0] = QString(depth * 2, ' ') + v[0];
            lines << v.join('\t');
            walk(m_proxy->index(r, 0, parent), depth + 1);
        }
    };
    walk({}, 0);
    Node *n = selectedNode();
    if (m_lower->isVisible() && n) {
        auto *m = static_cast<ListModel *>(m_lowerProxy->sourceModel());
        lines << QString() << QStringLiteral("Process: %1 Pid: %2").arg(n->info.name).arg(n->pid) << QString() << m->headers().join('\t');
        for (const auto &row : m->rows()) {
            QStringList v;
            for (const QVariant &x : row)
                v << x.toString();
            lines << v.join('\t');
        }
    }
    QFile f(m_savePath);
    if (f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        f.write((lines.join('\n') + '\n').toUtf8());
        statusBar()->showMessage(tr("Saved to %1").arg(m_savePath), 4000);
    } else {
        QMessageBox::warning(this, tr("Save"), f.errorString());
    }
}

void MainWindow::runProgram(bool admin)
{
    bool ok;
    QString text = QInputDialog::getText(this, admin ? tr("Run as Administrator") : tr("Run"),
                                         tr("Type the name of a program to open:"), QLineEdit::Normal, {}, &ok);
    QStringList args = QProcess::splitCommand(text);
    if (!ok || args.isEmpty())
        return;
    QString prog = admin ? QStringLiteral("pkexec") : args.takeFirst();
    if (!QProcess::startDetached(prog, args))
        QMessageBox::warning(this, tr("Run"), tr("Unable to start %1").arg(text));
}

void MainWindow::selectColumns()
{
    QHeaderView *h = m_tree->header();
    QSet<int> hidden;
    for (int i = 0; i < ColCount; ++i)
        if (h->isSectionHidden(i))
            hidden.insert(i);
    ColumnsDialog d(this, hidden);
    if (d.exec() == QDialog::Accepted) {
        const QSet<int> vis = d.visibleColumns();
        for (int i = 0; i < ColCount; ++i)
            h->setSectionHidden(i, !vis.contains(i));
    }
}

void MainWindow::configureColors()
{
    ColorsDialog d(this, m_model->colors());
    if (d.exec() != QDialog::Accepted)
        return;
    const ColorSet c = d.result();
    for (int i = 0; i < CatCount; ++i)
        m_settings.setValue(QStringLiteral("colors/") + COLOR_CATS[i].id, c[size_t(i)].isValid() ? c[size_t(i)].name() : QStringLiteral("none"));
    m_model->setColors(c);
}

void MainWindow::setPaused(bool on)
{
    m_paused = on;
    if (on)
        m_timer->stop();
    else
        m_timer->start(m_interval);
    m_stPaused->setText(on ? tr("Paused") : QString());
}

void MainWindow::setSpeed(int ms)
{
    m_interval = ms;
    if (!m_paused)
        m_timer->start(ms);
}

void MainWindow::setTray(bool on)
{
    if (on && QSystemTrayIcon::isSystemTrayAvailable()) {
        if (!m_tray) {
            m_tray = new QSystemTrayIcon(appIcon(), this);
            connect(m_tray, &QSystemTrayIcon::activated, this, [this] { showNormal(); raise(); activateWindow(); });
            auto *m = new QMenu(this);
            m->addAction(tr("Show Process Explorer"), this, [this] { showNormal(); raise(); });
            m->addAction(aSysInfo);
            m->addSeparator();
            m->addAction(aExit);
            m_tray->setContextMenu(m);
        }
        m_tray->show();
    } else if (m_tray) {
        m_tray->hide();
    }
}

void MainWindow::updateTray()
{
    if (!m_tray || !m_tray->isVisible())
        return;
    QPixmap pm(22, 22);
    pm.fill(Qt::black);
    QPainter p(&pm);
    const FRing &c = m_history.cpu;
    const int n = std::min(22, c.size());
    for (int i = 0; i < n; ++i) {
        int hgt = qRound(c.back(n - 1 - i) / 100.0 * 22);
        p.fillRect(22 - n + i, 22 - hgt, 1, hgt, pal::Cpu);
    }
    p.end();
    m_tray->setIcon(QIcon(pm));
    m_tray->setToolTip(tr("CPU Usage: %1%\n%2").arg(fdec(m_history.last.cpu), m_history.top.empty() ? QString() : m_history.top.back()));
}

void MainWindow::closeEvent(QCloseEvent *e)
{
    m_settings.setValue("geometry", saveGeometry());
    m_settings.setValue("splitter", m_split->saveState());
    m_settings.setValue("header", m_tree->header()->saveState());
    m_settings.setValue("interval", m_interval);
    m_settings.setValue("confirmKill", m_confirmKill);
    m_settings.setValue("lowerMode", m_lowerMode == LowerDlls ? "dlls" : "handles");
    m_settings.setValue("lowerPane", m_lower->isVisible());
    m_settings.setValue("treeMode", m_model->treeMode());
    m_settings.setValue("hideKthreads", m_proxy->hideKThreads());
    m_settings.setValue("highlight", m_model->highlight);
    m_settings.setValue("onTop", aOnTop->isChecked());
    m_settings.setValue("tray", aTray->isChecked());
    m_timer->stop();
    if (m_tray)
        m_tray->hide();
    e->accept();
    QApplication::quit();
}
