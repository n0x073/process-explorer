// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Process Exp contributors

#include "mainwindow.h"
#include "procfs.h"

#include <QApplication>
#include <QDir>
#include <QIcon>

#include <cerrno>
#include <cstdio>
#include <cstring>

// Elevated helper used through pkexec:  process-exp --signal SIG PID:START [PID:START ...]
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
            fprintf(stderr, "process-exp: pid %d: %s\n", pid, strerror(e));
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
    QApplication::setApplicationName(QStringLiteral("Process Exp"));
    QApplication::setDesktopFileName(QStringLiteral("process-exp"));
    qRegisterMetaType<SnapshotPtr>();

    // Qt already derives icon paths from XDG_DATA_DIRS; only add what is missing
    QStringList paths = QIcon::themeSearchPaths();
    for (QString &p : paths)
        p = QDir::cleanPath(p);
    for (const QString &d : pf::dataDirs(QStringLiteral("icons")))
        if (!paths.contains(d))
            paths << d;
    QIcon::setThemeSearchPaths(paths);
    QStringList fallback = QIcon::fallbackSearchPaths();
    for (const QString &d : pf::dataDirs(QStringLiteral("pixmaps")))
        if (!fallback.contains(d))
            fallback << d;
    QIcon::setFallbackSearchPaths(fallback);

    MainWindow w;
    w.show();
    return app.exec();
}
