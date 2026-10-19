#pragma once
#include "processmodel.h"
#include "types.h"
#include "widgets.h"

#include <QMainWindow>
#include <QPointer>
#include <QSettings>
#include <QThread>

class QAction;
class QActionGroup;
class QLabel;
class QLineEdit;
class QMenu;
class QSortFilterProxyModel;
class QSplitter;
class QSystemTrayIcon;
class QTableView;
class QTimer;
class QTreeView;
class Collector;
class FindDialog;
class SystemInfoDialog;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    enum LowerMode { LowerHandles, LowerDlls };
    MainWindow();
    ~MainWindow() override;

    ProcessModel *model() const { return m_model; }
    int interval() const { return m_interval; }
    // processes are addressed by key (pid + start time), never by bare pid
    void killProcess(quint64 key, const QString &name, bool tree, int sig);
    void suspendProcess(quint64 key, bool suspend);
    void selectPid(int pid, LowerMode lower, bool showLower = true);

signals:
    void requestCollect();
    void ticked();

protected:
    void closeEvent(QCloseEvent *e) override;

private slots:
    void onSnapshot(SnapshotPtr snap);

private:
    void buildTree();
    void buildLower();
    void buildActions();
    void buildMenus();
    void buildToolbar();
    void buildStatus();
    void fillProcessMenu(QMenu *m);
    QAction *act(const QString &text, const QString &shortcut = {}, const QString &icon = {}, bool checkable = false);

    void request();
    void expandInitial();
    void headerClicked(int col);
    void refreshLower();
    void setLowerMode(LowerMode m, bool show = false);
    Node *selectedNode() const;
    Node *aliveSelected() const;
    QVector<int> visibleColumns() const;

    void signalProcesses(const QVector<quint64> &keys, int sig, const QString &what);
    void elevate(const QString &program, const QStringList &args, const QString &err);
    void killSelected(bool tree, int sig);
    void toggleSuspendSelected();
    void restartSelected();
    void setPriority(int nice);
    void setAffinity();
    void showProperties();
    void showSysInfo();
    void showFind();
    void findWindowProcess();
    void copySelected();
    void save(bool ask);
    void runProgram(bool admin);
    void selectColumns();
    void configureColors();
    void setTray(bool on);
    void updateTray();
    void setPaused(bool on);
    void setSpeed(int ms);

    QSettings m_settings;
    ProcessModel *m_model;
    ProcProxy *m_proxy;
    QTreeView *m_tree;
    QTableView *m_lower;
    ListModel *m_handleModel, *m_dllModel;
    QSortFilterProxyModel *m_lowerProxy;
    QSplitter *m_split;
    QLineEdit *m_filter = nullptr;
    QLabel *m_stCpu, *m_stCommit, *m_stProcs, *m_stPhys, *m_stPaused;
    QVector<Graph *> m_tbGraphs;
    SysHistory m_history;
    QThread m_thread;
    Collector *m_collector;
    QTimer *m_timer;
    QSystemTrayIcon *m_tray = nullptr;
    QPointer<SystemInfoDialog> m_sysinfo;
    QPointer<FindDialog> m_find;
    QString m_savePath;

    int m_interval = 1000;
    bool m_pending = false, m_initialDone = false, m_paused = false, m_confirmKill = true;
    LowerMode m_lowerMode = LowerHandles;
    int m_sortCol = -1, m_sortClicks = 0;

    QAction *aRun, *aRunAdm, *aSave, *aSaveAs, *aExit, *aOnTop, *aConfirm, *aTray, *aHighlight, *aColors;
    QAction *aSysInfo, *aTreeMode, *aLower, *aHandles, *aDlls, *aRefresh, *aPause, *aColumns, *aKThreads;
    QAction *aProps, *aKill, *aKillTree, *aTerm, *aRestart, *aSuspend, *aAffinity, *aOpenLoc, *aSearch, *aCopy;
    QAction *aFind, *aFindWindow, *aFilter, *aAbout;
    QVector<QAction *> m_speedActs;
    QMenu *m_prioMenu;
    QHash<int, QAction *> m_prioActs;
};
