// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Process Exp contributors

#pragma once
// Thin helpers around /proc and /sys plus number formatting.
#include <QHash>
#include <QString>
#include <QStringList>
#include <QVector>

namespace pf {

extern const long CLK_TCK;
extern const long PAGE_SIZE;

// Read a small file into buf (NUL terminated). Returns length or -1.
int readSmall(const char *path, char *buf, int cap);
QByteArray readFile(const QString &path, qint64 max = 4 << 20);
QString readText(const QString &path);
QString readLink(const QString &path);
QHash<QString, QString> parseStatus(int pid);
qint64 kbField(const QHash<QString, QString> &status, const QString &key); // bytes or -1
QHash<QString, qint64> meminfo();                                         // bytes
QStringList decodeCaps(const QString &hex);
QString userName(uint uid);
QString groupName(uint gid);
QStringList cmdlineArgs(int pid);
quint64 startTime(int pid); // stat field 22, 0 if gone

// Race free process signalling. A pidfd always refers to the exact process it was
// opened for, so a PID that gets reused later can never receive our signal.
// openPidfd() additionally checks the start time so we never open the wrong
// process in the first place. Returns fd, or -1 with errno set (ESRCH = gone).
int openPidfd(int pid, quint64 start);
int sendSignal(int pidfd, int sig);           // 0 or errno
bool waitExit(int pidfd, int timeoutMs);      // true once the process has exited
int signalProcess(int pid, quint64 start, int sig); // 0 or errno
QString findGpu();

// Existing "<datadir>/<sub>" directories in XDG priority order: XDG_DATA_HOME,
// then XDG_DATA_DIRS. Flatpak and snap export dirs are appended as fallback in
// case the session was started without their profile.d scripts.
QStringList dataDirs(const QString &sub);

struct ThreadRow {
    int tid;
    QString name;
    char state;
    quint64 ticks;
    double utime, stime;
    int prio, nice, cpu;
    QString wchan;
};
QVector<ThreadRow> readThreads(int pid);
QVector<int> threadIds(int pid);

QHash<QString, QString> socketMap(int pid); // inode -> description
struct HandleRow { QString type, name; int fd; };
QVector<HandleRow> readHandles(int pid, const QHash<QString, QString> *sockets);
struct MapRow { QString name, path; quint64 base, size; QString mapping; };
QVector<MapRow> readMaps(int pid);
struct ConnRow { QString proto, local, remote, state; };
QVector<ConnRow> readConnections(int pid);

// formatting (system locale)
QString num(qint64 v);
QString fdec(double v, int prec = 2);
QString fmtK(qint64 bytes);
QString fmtBytes(double bytes);
QString fmtRate(double bytesPerSec);
QString fmtCpu(double pct);
QString fmtTime(double sec);
QString fmtDateTime(double epoch);

} // namespace pf

class DesktopIndex {
public:
    struct Entry { QString name, comment, icon; };
    DesktopIndex();
    const Entry *lookup(const QString &name, const QString &exe, const QString &flatpak) const;

private:
    QVector<Entry> m_entries;
    struct Slot { int idx, rank; };
    QHash<QString, Slot> m_byKey;
};
