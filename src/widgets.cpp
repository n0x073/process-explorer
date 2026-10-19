// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Process Exp contributors

#include "widgets.h"
#include "procfs.h"

#include <QDateTime>
#include <QMouseEvent>
#include <QPainter>
#include <QPolygonF>
#include <QToolTip>

using namespace pf;

namespace pal {
const QColor Cpu(0x00, 0xff, 0x00), Kernel(0xff, 0x00, 0x00), Commit(0xff, 0xff, 0x00),
    Phys(0xff, 0x99, 0x00), Read(0x00, 0xcc, 0xff), Write(0xff, 0x66, 0xcc), Gpu(0x33, 0xff, 0xff);
}
static const QColor GRID(0, 0x70, 0);

// ------------------------------------------------------------------ Graph
Graph::Graph(double maxValue, const QString &title, int minH, QWidget *parent)
    : QWidget(parent), m_max(maxValue), m_title(title)
{
    setMouseTracking(true);
    setMinimumSize(40, minH);
    setAttribute(Qt::WA_OpaquePaintEvent);
}

void Graph::addSeries(const FRing *data, const QColor &c, bool fill) { m_series.push_back({data, c, fill}); }

void Graph::advance()
{
    ++m_tick;
    if (isVisible())
        update();
}

void Graph::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    const int w = width(), h = height();
    p.fillRect(rect(), Qt::black);
    constexpr int gs = 12;
    p.setPen(GRID);
    for (int x = w - 1 - (m_tick * m_step) % gs; x >= 0; x -= gs)
        p.drawLine(x, 0, x, h);
    for (int y = h - 1; y >= 0; y -= gs)
        p.drawLine(0, y, w, y);

    double sc = m_max;
    if (sc <= 0) {
        float m = 0;
        for (const S &s : m_series)
            m = std::max(m, s.d->maxValue());
        sc = m > 0 ? m * 1.15 : 1.0;
    }
    const int maxPts = w / m_step + 2;
    QPolygonF pts;
    for (const S &s : m_series) {
        int n = std::min(s.d->size(), maxPts);
        if (n == 0)
            continue;
        pts.resize(n);
        double x0 = w - 1 - (n - 1) * m_step;
        for (int i = 0; i < n; ++i) {
            double v = std::clamp<double>(s.d->back(n - 1 - i), 0.0, sc);
            pts[i] = QPointF(x0 + i * m_step, h - 1 - v / sc * (h - 2));
        }
        if (s.fill) {
            QColor fc = s.c;
            fc.setAlpha(90);
            QPolygonF poly;
            poly.reserve(n + 2);
            poly << QPointF(pts.first().x(), h) << pts << QPointF(pts.last().x(), h);
            p.setPen(Qt::NoPen);
            p.setBrush(fc);
            p.drawPolygon(poly);
        }
        p.setPen(s.c);
        p.drawPolyline(pts);
    }
    if (!m_title.isEmpty() || valueFn) {
        QFont f = font();
        f.setPointSizeF(std::max(7.0, f.pointSizeF() - 1));
        p.setFont(f);
        p.setPen(QColor(0x9c, 0xff, 0x9c));
        QString t = m_title;
        if (valueFn)
            t += (t.isEmpty() ? QString() : QStringLiteral("  ")) + valueFn();
        p.drawText(QRect(4, 2, w - 8, 16), Qt::AlignLeft, t);
    }
}

void Graph::mouseMoveEvent(QMouseEvent *e)
{
    if (!tooltipFn)
        return;
    int back = std::max(0, int((width() - 1 - e->position().x()) / m_step));
    QString t = tooltipFn(back);
    if (!t.isEmpty())
        QToolTip::showText(e->globalPosition().toPoint(), t, this);
}

void Graph::mousePressEvent(QMouseEvent *e)
{
    if (e->button() == Qt::LeftButton)
        emit clicked();
}

// ------------------------------------------------------------------ Meter
Meter::Meter(std::function<double()> value, const QColor &c, QWidget *parent)
    : QWidget(parent), m_value(std::move(value)), m_color(c)
{
    setFixedWidth(64);
}

void Meter::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    const int w = width(), h = height();
    p.fillRect(rect(), Qt::black);
    double v = std::clamp(m_value(), 0.0, 100.0);
    int barH = h - 20, segs = std::max(1, barH / 3), lit = qRound(segs * v / 100);
    QColor dim = m_color.darker(400);
    for (int s = 0; s < segs; ++s)
        p.fillRect(14, barH - (s + 1) * 3 + 2, w - 28, 2, s < lit ? m_color : dim);
    p.setPen(m_color);
    p.drawText(QRect(0, h - 18, w, 16), Qt::AlignCenter, fdec(v) + '%');
}

// ------------------------------------------------------------------ ListModel
void ListModel::setRows(QVector<Row> rows)
{
    if (!rows.isEmpty() && rows.size() == m_rows.size()) {
        m_rows = std::move(rows);
        emit dataChanged(index(0, 0), index(m_rows.size() - 1, m_headers.size() - 1));
    } else {
        beginResetModel();
        m_rows = std::move(rows);
        endResetModel();
    }
}

QVariant ListModel::headerData(int s, Qt::Orientation o, int role) const
{
    if (o == Qt::Horizontal && role == Qt::DisplayRole)
        return m_headers.value(s);
    return {};
}

QVariant ListModel::data(const QModelIndex &idx, int role) const
{
    if (!idx.isValid())
        return {};
    const QVariant &v = m_rows[idx.row()][idx.column()];
    const int c = idx.column();
    switch (role) {
    case Qt::DisplayRole:
        if (auto it = m_fmt.find(c); it != m_fmt.end())
            return (*it)(v);
        return v.toString();
    case Qt::ToolTipRole:
        return v.toString();
    case SortRole:
        return m_numeric.contains(c) ? v : QVariant(v.toString().toLower());
    case Qt::TextAlignmentRole:
        if (m_numeric.contains(c))
            return QVariant::fromValue(Qt::AlignRight | Qt::AlignVCenter);
        break;
    }
    return {};
}

// ------------------------------------------------------------------ SysHistory
SysHistory::SysHistory(int ncpu) : percpu(size_t(ncpu)) {}

void SysHistory::add(const Snapshot &snap)
{
    const SysInfo &s = snap.sys;
    last = s;
    hasLast = true;
    cpu.push(float(s.cpu));
    kern.push(float(s.kernel));
    for (size_t i = 0; i < percpu.size(); ++i)
        percpu[i].push(i < size_t(s.percpu.size()) ? float(s.percpu[int(i)]) : 0.f);
    commit.push(float(s.commitPct));
    phys.push(float(s.physPct));
    swap.push(float(s.swapPct));
    diskR.push(float(s.diskR));
    diskW.push(float(s.diskW));
    diskT.push(float(s.diskR + s.diskW));
    netRx.push(float(s.netRx));
    netTx.push(float(s.netTx));
    if (s.gpu >= 0)
        hasGpu = true;
    gpu.push(float(std::max(0.0, s.gpu)));
    const ProcInfo *t = nullptr;
    for (const ProcInfo &p : snap.procs)
        if (p.pid > 0 && (!t || p.cpu > t->cpu))
            t = &p;
    top.push(t ? QStringLiteral("%1 (%2): %3%").arg(t->name).arg(t->pid).arg(fdec(t->cpu)) : QString());
    times.push(snap.time);
}

QString SysHistory::tip(const QString &kind, int back) const
{
    if (back >= times.size())
        return {};
    auto at = [back](const FRing &r) { return back < r.size() ? double(r.back(back)) : 0.0; };
    QString t = QDateTime::fromMSecsSinceEpoch(qint64(times.back(back) * 1000)).toString(QStringLiteral("HH:mm:ss"));
    auto rate = [](double v) { return v > 0 ? fmtRate(v) : QStringLiteral("0 B/s"); };
    if (kind == QLatin1String("cpu"))
        return QStringLiteral("CPU Usage: %1%\nKernel: %2%\n%3\n%4").arg(fdec(at(cpu)), fdec(at(kern)), top.back(back), t);
    if (kind == QLatin1String("commit"))
        return QStringLiteral("Commit Charge: %1%\n%2").arg(fdec(at(commit)), t);
    if (kind == QLatin1String("phys"))
        return QStringLiteral("Physical Memory: %1%\n%2").arg(fdec(at(phys)), t);
    if (kind == QLatin1String("io"))
        return QStringLiteral("Disk Read: %1\nDisk Write: %2\n%3").arg(rate(at(diskR)), rate(at(diskW)), t);
    if (kind == QLatin1String("net"))
        return QStringLiteral("Receive: %1\nSend: %2\n%3").arg(rate(at(netRx)), rate(at(netTx)), t);
    if (kind == QLatin1String("gpu"))
        return QStringLiteral("GPU Usage: %1%\n%2").arg(fdec(at(gpu)), t);
    if (kind.startsWith(QLatin1String("cpu"))) {
        int i = kind.mid(3).toInt();
        if (i >= 0 && size_t(i) < percpu.size())
            return QStringLiteral("CPU %1: %2%\n%3").arg(i).arg(fdec(at(percpu[size_t(i)])), t);
    }
    return {};
}
