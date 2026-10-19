#pragma once
#include <QMetaType>
#include <QString>
#include <QVector>
#include <memory>

// A process key packs (starttime << 22) | pid; pid_max is at most 2^22.
inline int keyPid(quint64 key) { return int(key & ((1u << 22) - 1)); }
inline quint64 keyStart(quint64 key) { return key >> 22; }

enum class Kind : quint8 { Normal, Idle, KThread, Service, Flatpak };

struct ProcInfo {
    quint64 key = 0;          // (starttime << 22) | pid  -> unique across pid reuse
    int pid = 0, ppid = 0;
    quint64 start = 0;        // starttime in clock ticks since boot
    double ctime = 0;         // epoch seconds
    QString name, comm, exe, cmdline, user, cgroup, unit, flatpak;
    uint uid = 0;
    Kind kind = Kind::Normal;
    bool own = false;
    char state = '?';
    double utime = 0, stime = 0, cpu = 0, ioDelta = 0;
    qint64 rss = -1, vms = -1, shared = -1, priv = -1;
    qint64 ioR = -1, ioW = -1;
    int threads = 0, fds = -1, nice = 0;
    bool hasNice = true;

    double cputime() const { return utime + stime; }
    bool stopped() const { return state == 'T' || state == 't'; }
};

struct SysInfo {
    double cpu = 0, idle = 100, kernel = 0, iowait = 0;
    QVector<double> percpu;
    qint64 memTotal = 0, memAvail = 0, memUsed = 0, cached = 0, buffers = 0, shmem = 0;
    qint64 slab = 0, sreclaim = 0, kstack = 0, pagetables = 0, dirty = 0;
    qint64 swapTotal = 0, swapUsed = 0, commit = 0, commitLimit = 1;
    double physPct = 0, swapPct = 0, commitPct = 0;
    double load[3] = {0, 0, 0};
    double boot = 0;
    double diskR = 0, diskW = 0, diskROps = 0, diskWOps = 0, netRx = 0, netTx = 0, ctx = 0, intr = 0;
    qint64 diskTotR = 0, diskTotW = 0, netTotRx = 0, netTotTx = 0;
    double gpu = -1;
    qint64 vramUsed = 0, vramTotal = 0;
    int processes = 0, threads = 0, handles = 0;
};

struct Snapshot {
    double time = 0;
    QVector<ProcInfo> procs;
    SysInfo sys;
};
using SnapshotPtr = std::shared_ptr<const Snapshot>;
Q_DECLARE_METATYPE(SnapshotPtr)
