// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Process Exp contributors

#pragma once
#include "types.h"

#include <QDialog>
#include <QHash>

class QLabel;
class QGroupBox;
class Graph;
class SysHistory;

class InfoGroup;

class SystemInfoDialog : public QDialog {
    Q_OBJECT
public:
    SystemInfoDialog(SysHistory *h, QWidget *parent);

public slots:
    void refresh();

private:
    Graph *makeGraph(double max, const QString &title, int minH, const QString &tipKind);
    SysHistory *m_h;
    QVector<Graph *> m_graphs;
    QVector<QWidget *> m_meters;
    InfoGroup *m_cpu, *m_kern, *m_tot, *m_commit, *m_phys, *m_swap, *m_kmem, *m_disk, *m_net, *m_gpu = nullptr;
};
