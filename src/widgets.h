// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Process Exp contributors

#pragma once
// Ring buffers, PE style graphs and meters, a generic table model, system history.
#include "types.h"

#include <QAbstractTableModel>
#include <QColor>
#include <QHash>
#include <QSet>
#include <QVariant>
#include <QWidget>

#include <functional>
#include <vector>

constexpr int HIST = 300;
constexpr int SortRole = Qt::UserRole + 1;

template<typename T>
class Ring {
public:
    explicit Ring(int cap = HIST) : m_d(size_t(cap)) {}
    void push(const T &v)
    {
        m_d[size_t(m_head)] = v;
        m_head = (m_head + 1) % int(m_d.size());
        if (m_n < int(m_d.size()))
            ++m_n;
    }
    int size() const { return m_n; }
    bool empty() const { return m_n == 0; }
    // 0 == oldest
    const T &at(int i) const { return m_d[size_t((m_head - m_n + i + int(m_d.size())) % int(m_d.size()))]; }
    // 0 == newest
    const T &back(int i = 0) const { return at(m_n - 1 - i); }
    T maxValue() const
    {
        T m{};
        for (int i = 0; i < m_n; ++i)
            m = std::max(m, at(i));
        return m;
    }

private:
    std::vector<T> m_d;
    int m_head = 0, m_n = 0;
};
using FRing = Ring<float>;

namespace pal {
extern const QColor Cpu, Kernel, Commit, Phys, Read, Write, Gpu;
}

class Graph : public QWidget {
    Q_OBJECT
public:
    explicit Graph(double maxValue = 100.0, const QString &title = {}, int minH = 40, QWidget *parent = nullptr);
    void addSeries(const FRing *data, const QColor &c, bool fill = true);
    void advance();
    std::function<QString()> valueFn;
    std::function<QString(int)> tooltipFn; // arg: samples back from newest

signals:
    void clicked();

protected:
    void paintEvent(QPaintEvent *) override;
    void mouseMoveEvent(QMouseEvent *) override;
    void mousePressEvent(QMouseEvent *) override;

private:
    struct S { const FRing *d; QColor c; bool fill; };
    std::vector<S> m_series;
    double m_max;
    QString m_title;
    int m_tick = 0, m_step = 2;
};

class Meter : public QWidget {
public:
    Meter(std::function<double()> value, const QColor &c, QWidget *parent = nullptr);
    QSize sizeHint() const override { return {64, 80}; }

protected:
    void paintEvent(QPaintEvent *) override;

private:
    std::function<double()> m_value;
    QColor m_color;
};

// Rows are QVariant vectors; optional per column display formatter.
class ListModel : public QAbstractTableModel {
public:
    using Row = QVector<QVariant>;
    using Fmt = std::function<QString(const QVariant &)>;
    ListModel(const QStringList &headers, QObject *parent = nullptr) : QAbstractTableModel(parent), m_headers(headers) {}
    void setFormatter(int col, Fmt f) { m_fmt.insert(col, std::move(f)); }
    void setNumeric(std::initializer_list<int> cols) { for (int c : cols) m_numeric.insert(c); }
    void setRows(QVector<Row> rows);
    const QVector<Row> &rows() const { return m_rows; }
    const QStringList &headers() const { return m_headers; }

    int rowCount(const QModelIndex &p = {}) const override { return p.isValid() ? 0 : m_rows.size(); }
    int columnCount(const QModelIndex &p = {}) const override { return p.isValid() ? 0 : m_headers.size(); }
    QVariant headerData(int s, Qt::Orientation o, int role) const override;
    QVariant data(const QModelIndex &idx, int role) const override;

private:
    QStringList m_headers;
    QHash<int, Fmt> m_fmt;
    QSet<int> m_numeric;
    QVector<Row> m_rows;
};

class SysHistory {
public:
    explicit SysHistory(int ncpu);
    void add(const Snapshot &snap);
    QString tip(const QString &kind, int back) const;

    FRing cpu, kern, commit, phys, swap, diskR, diskW, diskT, netRx, netTx, gpu;
    std::vector<FRing> percpu;
    Ring<QString> top;
    Ring<double> times;
    SysInfo last;
    bool hasLast = false, hasGpu = false;
};
