#include "sysinfodialog.h"
#include "procfs.h"
#include "widgets.h"

#include <QCheckBox>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QTabWidget>
#include <QVBoxLayout>

#include <cmath>

using namespace pf;

class InfoGroup : public QGroupBox {
public:
    InfoGroup(const QString &title, const QStringList &keys) : QGroupBox(title)
    {
        auto *f = new QFormLayout(this);
        f->setHorizontalSpacing(20);
        for (const QString &k : keys) {
            auto *l = new QLabel;
            l->setMinimumWidth(110);
            l->setAlignment(Qt::AlignRight);
            f->addRow(k, l);
            m_labels.insert(k, l);
        }
    }
    void set(const QString &k, const QString &v) { if (QLabel *l = m_labels.value(k)) l->setText(v); }

private:
    QHash<QString, QLabel *> m_labels;
};

static QString uptime(double sec)
{
    qint64 s = qint64(sec);
    return QStringLiteral("%1:%2:%3:%4").arg(s / 86400).arg(s / 3600 % 24, 2, 10, QChar('0'))
        .arg(s / 60 % 60, 2, 10, QChar('0')).arg(s % 60, 2, 10, QChar('0'));
}

Graph *SystemInfoDialog::makeGraph(double max, const QString &title, int minH, const QString &tipKind)
{
    auto *g = new Graph(max, title, minH);
    SysHistory *h = m_h;
    g->tooltipFn = [h, tipKind](int b) { return h->tip(tipKind, b); };
    m_graphs << g;
    return g;
}

SystemInfoDialog::SystemInfoDialog(SysHistory *h, QWidget *parent) : QDialog(parent), m_h(h)
{
    setWindowTitle(tr("System Information"));
    resize(900, 680);
    auto *tabs = new QTabWidget;

    // ---------------------------------------------------- Summary
    auto *summ = new QWidget;
    auto *sg = new QVBoxLayout(summ);
    auto row = [&](const QString &title, std::function<double()> meter, const QColor &mc, Graph *g) {
        auto *box = new QGroupBox(title);
        auto *bl = new QHBoxLayout(box);
        if (meter) {
            auto *m = new Meter(meter, mc);
            m_meters << m;
            bl->addWidget(m);
        }
        bl->addWidget(g, 1);
        sg->addWidget(box, 1);
    };
    Graph *g = makeGraph(100, {}, 40, "cpu");
    g->addSeries(&h->cpu, pal::Cpu);
    g->addSeries(&h->kern, pal::Kernel);
    row(tr("CPU Usage"), [h] { return h->last.cpu; }, pal::Cpu, g);
    g = makeGraph(100, {}, 40, "commit");
    g->addSeries(&h->commit, pal::Commit);
    row(tr("Commit Charge"), [h] { return h->last.commitPct; }, pal::Commit, g);
    g = makeGraph(100, {}, 40, "phys");
    g->addSeries(&h->phys, pal::Phys);
    row(tr("Physical Memory"), [h] { return h->last.physPct; }, pal::Phys, g);
    g = makeGraph(0, {}, 40, "io");
    g->addSeries(&h->diskR, pal::Read);
    g->addSeries(&h->diskW, pal::Write, false);
    g->valueFn = [h] {
        auto r = [](double v) { return v > 0 ? fmtRate(v) : QStringLiteral("0 B/s"); };
        return QStringLiteral("R %1   W %2").arg(r(h->last.diskR), r(h->last.diskW));
    };
    row(tr("Disk I/O"), {}, {}, g);
    g = makeGraph(0, {}, 40, "net");
    g->addSeries(&h->netRx, pal::Read);
    g->addSeries(&h->netTx, pal::Write, false);
    g->valueFn = [h] {
        auto r = [](double v) { return v > 0 ? fmtRate(v) : QStringLiteral("0 B/s"); };
        return QStringLiteral("Rx %1   Tx %2").arg(r(h->last.netRx), r(h->last.netTx));
    };
    row(tr("Network"), {}, {}, g);
    if (h->hasGpu) {
        g = makeGraph(100, {}, 40, "gpu");
        g->addSeries(&h->gpu, pal::Gpu);
        row(tr("GPU"), [h] { return std::max(0.0, h->last.gpu); }, pal::Gpu, g);
    }
    tabs->addTab(summ, tr("Summary"));

    // ---------------------------------------------------- CPU
    auto *cpu = new QWidget;
    auto *cl = new QVBoxLayout(cpu);
    auto *one = new QCheckBox(tr("Show one graph per CPU"));
    one->setChecked(true);
    cl->addWidget(one);
    auto *coreArea = new QWidget;
    auto *cg = new QGridLayout(coreArea);
    cg->setSpacing(4);
    const int n = int(h->percpu.size());
    const int cols = std::max(1, int(std::ceil(std::sqrt(double(n)))));
    for (int i = 0; i < n; ++i) {
        Graph *cgph = makeGraph(100, tr("CPU %1").arg(i), 50, QStringLiteral("cpu%1").arg(i));
        const FRing *r = &h->percpu[size_t(i)];
        cgph->addSeries(r, pal::Cpu);
        cgph->valueFn = [r] { return r->empty() ? QString() : fdec(r->back(), 1) + '%'; };
        cg->addWidget(cgph, i / cols, i % cols);
    }
    Graph *total = makeGraph(100, tr("CPU Usage"), 200, "cpu");
    total->addSeries(&h->cpu, pal::Cpu);
    total->addSeries(&h->kern, pal::Kernel);
    total->hide();
    cl->addWidget(coreArea, 1);
    cl->addWidget(total, 1);
    connect(one, &QCheckBox::toggled, this, [coreArea, total](bool on) {
        coreArea->setVisible(on);
        total->setVisible(!on);
    });
    auto *hb = new QHBoxLayout;
    m_cpu = new InfoGroup(tr("CPU"), {"Usage", "Kernel", "I/O Wait", "Load Average", "Logical CPUs"});
    m_kern = new InfoGroup(tr("Kernel"), {"Context Switch Delta", "Interrupt Delta", "Uptime"});
    m_tot = new InfoGroup(tr("Totals"), {"Processes", "Threads", "Handles (FDs)"});
    hb->addWidget(m_cpu);
    hb->addWidget(m_kern);
    hb->addWidget(m_tot);
    cl->addLayout(hb);
    tabs->addTab(cpu, tr("CPU"));

    // ---------------------------------------------------- Memory
    auto *mem = new QWidget;
    auto *ml = new QVBoxLayout(mem);
    g = makeGraph(100, tr("Commit Charge"), 110, "commit");
    g->addSeries(&h->commit, pal::Commit);
    g->valueFn = [h] { return fdec(h->last.commitPct, 1) + '%'; };
    ml->addWidget(g, 1);
    g = makeGraph(100, tr("Physical Memory"), 110, "phys");
    g->addSeries(&h->phys, pal::Phys);
    g->valueFn = [h] { return fdec(h->last.physPct, 1) + '%'; };
    ml->addWidget(g, 1);
    auto *mg = new QGridLayout;
    m_commit = new InfoGroup(tr("Commit Charge (K)"), {"Current", "Limit", "Usage"});
    m_swap = new InfoGroup(tr("Swap (K)"), {"Total", "Used", "Usage"});
    m_phys = new InfoGroup(tr("Physical Memory (K)"), {"Total", "Available", "Used", "Cache", "Buffers", "Shared"});
    m_kmem = new InfoGroup(tr("Kernel Memory (K)"), {"Slab", "Slab Reclaimable", "Kernel Stack", "Page Tables", "Dirty"});
    mg->addWidget(m_commit, 0, 0);
    mg->addWidget(m_swap, 1, 0);
    mg->addWidget(m_phys, 0, 1, 2, 1);
    mg->addWidget(m_kmem, 0, 2, 2, 1);
    ml->addLayout(mg);
    tabs->addTab(mem, tr("Memory"));

    // ---------------------------------------------------- I/O
    auto *io = new QWidget;
    auto *il = new QVBoxLayout(io);
    g = makeGraph(0, tr("Disk I/O (read cyan / write pink)"), 130, "io");
    g->addSeries(&h->diskR, pal::Read);
    g->addSeries(&h->diskW, pal::Write, false);
    il->addWidget(g, 1);
    g = makeGraph(0, tr("Network (receive cyan / send pink)"), 130, "net");
    g->addSeries(&h->netRx, pal::Read);
    g->addSeries(&h->netTx, pal::Write, false);
    il->addWidget(g, 1);
    auto *ih = new QHBoxLayout;
    m_disk = new InfoGroup(tr("Disk"), {"Read/s", "Write/s", "Read Ops/s", "Write Ops/s", "Total Read", "Total Written"});
    m_net = new InfoGroup(tr("Network"), {"Receive/s", "Send/s", "Total Received", "Total Sent"});
    ih->addWidget(m_disk);
    ih->addWidget(m_net);
    il->addLayout(ih);
    tabs->addTab(io, tr("I/O"));

    // ---------------------------------------------------- GPU
    if (h->hasGpu) {
        auto *gpu = new QWidget;
        auto *gl = new QVBoxLayout(gpu);
        g = makeGraph(100, tr("GPU Usage"), 200, "gpu");
        g->addSeries(&h->gpu, pal::Gpu);
        gl->addWidget(g, 1);
        m_gpu = new InfoGroup(tr("GPU"), {"Usage", "VRAM Used", "VRAM Total"});
        gl->addWidget(m_gpu);
        tabs->addTab(gpu, tr("GPU"));
    }

    auto *bb = new QDialogButtonBox(QDialogButtonBox::Close);
    connect(bb, &QDialogButtonBox::rejected, this, &QDialog::close);
    auto *lay = new QVBoxLayout(this);
    lay->addWidget(tabs);
    lay->addWidget(bb);
    refresh();
}

void SystemInfoDialog::refresh()
{
    if (!m_h->hasLast)
        return;
    for (Graph *g : std::as_const(m_graphs))
        g->advance();
    if (!isVisible())
        return;
    for (QWidget *m : std::as_const(m_meters))
        m->update();
    const SysInfo &s = m_h->last;
    auto pct = [](double v) { return fdec(v) + '%'; };
    m_cpu->set("Usage", pct(s.cpu));
    m_cpu->set("Kernel", pct(s.kernel));
    m_cpu->set("I/O Wait", pct(s.iowait));
    m_cpu->set("Load Average", QStringLiteral("%1 / %2 / %3").arg(fdec(s.load[0]), fdec(s.load[1]), fdec(s.load[2])));
    m_cpu->set("Logical CPUs", QString::number(s.percpu.size()));
    m_kern->set("Context Switch Delta", num(qint64(s.ctx)));
    m_kern->set("Interrupt Delta", num(qint64(s.intr)));
    m_kern->set("Uptime", uptime(QDateTime::currentMSecsSinceEpoch() / 1000.0 - s.boot));
    m_tot->set("Processes", num(s.processes));
    m_tot->set("Threads", num(s.threads));
    m_tot->set("Handles (FDs)", num(s.handles));
    m_commit->set("Current", fmtK(s.commit));
    m_commit->set("Limit", fmtK(s.commitLimit));
    m_commit->set("Usage", pct(s.commitPct));
    m_phys->set("Total", fmtK(s.memTotal));
    m_phys->set("Available", fmtK(s.memAvail));
    m_phys->set("Used", fmtK(s.memUsed));
    m_phys->set("Cache", fmtK(s.cached));
    m_phys->set("Buffers", fmtK(s.buffers));
    m_phys->set("Shared", fmtK(s.shmem));
    m_swap->set("Total", fmtK(s.swapTotal));
    m_swap->set("Used", fmtK(s.swapUsed));
    m_swap->set("Usage", pct(s.swapPct));
    m_kmem->set("Slab", fmtK(s.slab));
    m_kmem->set("Slab Reclaimable", fmtK(s.sreclaim));
    m_kmem->set("Kernel Stack", fmtK(s.kstack));
    m_kmem->set("Page Tables", fmtK(s.pagetables));
    m_kmem->set("Dirty", fmtK(s.dirty));
    auto rate = [](double v) { return v > 0 ? fmtRate(v) : QStringLiteral("0"); };
    m_disk->set("Read/s", rate(s.diskR));
    m_disk->set("Write/s", rate(s.diskW));
    m_disk->set("Read Ops/s", num(qint64(s.diskROps)));
    m_disk->set("Write Ops/s", num(qint64(s.diskWOps)));
    m_disk->set("Total Read", fmtBytes(double(s.diskTotR)));
    m_disk->set("Total Written", fmtBytes(double(s.diskTotW)));
    m_net->set("Receive/s", rate(s.netRx));
    m_net->set("Send/s", rate(s.netTx));
    m_net->set("Total Received", fmtBytes(double(s.netTotRx)));
    m_net->set("Total Sent", fmtBytes(double(s.netTotTx)));
    if (m_gpu) {
        m_gpu->set("Usage", pct(std::max(0.0, s.gpu)));
        m_gpu->set("VRAM Used", fmtBytes(double(s.vramUsed)));
        m_gpu->set("VRAM Total", fmtBytes(double(s.vramTotal)));
    }
}
