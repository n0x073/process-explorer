// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Process Exp contributors

#pragma once
#include "procfs.h"
#include "types.h"
#include "widgets.h"

#include <QAbstractItemModel>
#include <QIcon>
#include <QSortFilterProxyModel>

enum Col {
    ColName, ColCpu, ColPrivate, ColWs, ColPid, ColDesc, ColUser, ColThreads, ColHandles, ColNice,
    ColVSize, ColCpuTime, ColStart, ColIoDelta, ColIoR, ColIoW, ColStatus, ColUnit, ColPpid, ColPath,
    ColCmdline, ColCount
};
struct ColumnDef { const char *id, *title; int width; bool numeric, visible; };
extern const ColumnDef COLUMNS[ColCount];

enum ColorCat { CatNew, CatDying, CatSuspended, CatFlatpak, CatService, CatKThread, CatOwn, CatCount };
struct ColorDef { const char *id, *label, *def; };
extern const ColorDef COLOR_CATS[CatCount];
using ColorSet = std::array<QColor, CatCount>; // invalid colour == category disabled

struct Node {
    enum State { Normal, New, Dying };
    quint64 key = 0;
    int pid = 0;
    ProcInfo info;
    State state = Normal;
    double until = 0;
    Node *parent = nullptr;
    QVector<Node *> children;
    int row = 0;
    bool dirty = true;
    FRing hCpu, hPriv, hWs, hIo;
    QIcon icon;
    QString desc, comment, search;
    void pushHist();
    QString tooltip() const;
};

class ProcessModel : public QAbstractItemModel {
    Q_OBJECT
public:
    explicit ProcessModel(QObject *parent = nullptr);
    ~ProcessModel() override;

    void update(const Snapshot &snap);
    void setTreeMode(bool on);
    bool treeMode() const { return m_tree; }
    void setColors(const ColorSet &c);
    const ColorSet &colors() const { return m_colors; }
    double highlight = 2.0;

    Node *node(quint64 key) const { return m_nodes.value(key); }
    Node *findPid(int pid) const;
    const QHash<quint64, Node *> &nodes() const { return m_nodes; }
    QModelIndex indexOf(Node *n, int col = 0) const;
    QString display(const Node *n, int col) const;

    int columnCount(const QModelIndex & = {}) const override { return ColCount; }
    int rowCount(const QModelIndex &parent = {}) const override;
    QModelIndex index(int row, int col, const QModelIndex &parent = {}) const override;
    QModelIndex parent(const QModelIndex &idx) const override;
    using QObject::parent;
    QVariant headerData(int s, Qt::Orientation o, int role) const override;
    QVariant data(const QModelIndex &idx, int role) const override;

private:
    QVector<Node *> &list(Node *n) { return n ? n->children : m_roots; }
    const QVector<Node *> &list(Node *n) const { return n ? n->children : m_roots; }
    QColor colorOf(const Node *n) const;
    QVariant sortValue(const Node *n, int col) const;
    void decorate(Node *n);
    QIcon icon(const QString &name);
    Node *wantParent(Node *n, const QHash<int, Node *> &byPid) const;
    void insert(Node *n, Node *parent);
    void move(Node *n, Node *newParent);
    void remove(Node *n);
    void emitChanged(bool all);
    static void reindex(QVector<Node *> &l, int from);

    QHash<quint64, Node *> m_nodes;
    QVector<Node *> m_roots;
    bool m_tree = true, m_initialized = false;
    ColorSet m_colors;
    DesktopIndex m_desktop;
    QHash<QString, QIcon> m_icons;
    QIcon m_default, m_kernel, m_wine;
};

class ProcProxy : public QSortFilterProxyModel {
    Q_OBJECT
public:
    explicit ProcProxy(QObject *parent = nullptr);
    void setText(const QString &t);
    void setHideKThreads(bool on);
    bool hideKThreads() const { return m_hideK; }

protected:
    bool filterAcceptsRow(int row, const QModelIndex &parent) const override;

private:
    QString m_text;
    bool m_hideK = false;
};

ColorSet defaultColors();
