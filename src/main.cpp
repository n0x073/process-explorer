#include "mainwindow.h"

#include <QApplication>
#include <QDir>
#include <QIcon>

#include <cerrno>
#include <cstdio>
#include <cstring>

// Elevated helper used through pkexec:  procexp --signal SIG PID:START [PID:START ...]
// Re-checks every process identity with a pidfd, so the seconds spent in the
// password dialog cannot make us hit a reused PID.
static int signalHelper(int argc, char **argv)
{
    int sig = atoi(argv[2]);
    if (sig < 1 || sig > 64)
        return 2;
    int rc = 0;
    for (int i = 3; i < argc; ++i) {
        int pid;
        unsigned long long start;
        if (sscanf(argv[i], "%d:%llu", &pid, &start) != 2)
            return 2;
        int e = pf::signalProcess(pid, start, sig);
        if (e && e != ESRCH) {
            fprintf(stderr, "procexp: pid %d: %s\n", pid, strerror(e));
            rc = 1;
        }
    }
    return rc;
}

int main(int argc, char **argv)
{
    if (argc >= 4 && strcmp(argv[1], "--signal") == 0)
        return signalHelper(argc, argv);
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("Process Explorer"));
    QApplication::setDesktopFileName(QStringLiteral("procexp-linux"));
    qRegisterMetaType<SnapshotPtr>();

    QStringList paths = QIcon::themeSearchPaths();
    for (const QString &d : {QDir::homePath() + "/.local/share/flatpak/exports/share/icons",
                             QStringLiteral("/var/lib/flatpak/exports/share/icons")})
        if (QDir(d).exists())
            paths << d;
    QIcon::setThemeSearchPaths(paths);
    QIcon::setFallbackSearchPaths(QIcon::fallbackSearchPaths() << QStringLiteral("/usr/share/pixmaps"));

    MainWindow w;
    w.show();
    return app.exec();
}
