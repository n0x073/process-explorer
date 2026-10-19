// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Process Exp contributors

#pragma once
#include "types.h"

#include <QHash>
#include <QObject>
#include <QStringList>

// Samples all processes and system counters; lives in a worker thread.
class Collector : public QObject {
    Q_OBJECT
public:
    Collector();

public slots:
    void collect();

signals:
    void ready(SnapshotPtr snap);

private:
    struct Static {
        QString name, comm, exe, cmdline, user, cgroup, unit, flatpak;
        uint uid = 0;
        Kind kind = Kind::Normal;
        bool own = false;
    };
    struct Prev { quint64 ticks; qint64 io; };
    struct CpuTimes { quint64 total = 0, idle = 0, kernel = 0, iowait = 0; };

    Static makeStatic(int dirfd, bool kthread, const QString &comm);
    void readSystem(SysInfo &s, double dt);

    QHash<quint64, Static> m_static;
    QHash<quint64, Prev> m_prev;
    QVector<CpuTimes> m_prevCpu; // [0] = total, [1..] = per cpu
    qint64 m_lastNs = 0;
    int m_ncpu = 1;
    uint m_uid = 0;
    double m_btime = 0;
    QString m_gpuPath;
    QStringList m_disks;
    bool m_havePrevIo = false;
    quint64 m_prevDisk[4] = {}, m_prevNet[2] = {}, m_prevCtx = 0, m_prevIntr = 0;
};
