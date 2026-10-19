// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Process Exp contributors

#pragma once
#include "processmodel.h"

#include <QDialog>
#include <QHash>

class QCheckBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QPlainTextEdit;
class QPushButton;
class QRadioButton;
class QTabWidget;
class QTableView;
class MainWindow;
class Graph;

QTableView *makeTable(ListModel *model, int sortCol = -1, Qt::SortOrder order = Qt::AscendingOrder);

class PropertiesDialog : public QDialog {
    Q_OBJECT
public:
    PropertiesDialog(MainWindow *main, Node *n);

public slots:
    void refresh();

private:
    QWidget *imageTab(Node *n);
    QWidget *perfTab();
    QWidget *graphTab(Node *n);
    QWidget *threadsTab();
    QWidget *tcpTab();
    QWidget *securityTab();
    QWidget *envTab();
    QWidget *stringsTab();
    void refreshPerf(Node *n);
    void refreshThreads();
    void refreshTcp();
    void loadStrings();
    void verify(const QString &exe);

    MainWindow *m_main;
    quint64 m_key;
    int m_pid;
    QString m_name;
    QTabWidget *m_tabs;
    QHash<QString, QLabel *> m_perf;
    QVector<Graph *> m_graphs;
    ListModel *m_thrModel = nullptr, *m_tcpModel = nullptr;
    QLabel *m_thrCount = nullptr, *m_pkg = nullptr;
    QPushButton *m_suspend = nullptr;
    QHash<int, quint64> m_thrPrev;
    qint64 m_thrPrevNs = 0;
    QRadioButton *m_strImage = nullptr;
    QPlainTextEdit *m_strText = nullptr;
    QLineEdit *m_strFind = nullptr;
    bool m_stringsLoaded = false;
};

class FindDialog : public QDialog {
    Q_OBJECT
public:
    explicit FindDialog(MainWindow *main);
    void focusEdit();

private:
    void search();
    MainWindow *m_main;
    QLineEdit *m_edit;
    QPushButton *m_btn, *m_cancel;
    ListModel *m_model;
    QTableView *m_view;
    QLabel *m_status;
    bool m_stop = false;
};

class ColumnsDialog : public QDialog {
public:
    ColumnsDialog(QWidget *parent, const QSet<int> &hidden);
    QSet<int> visibleColumns() const;

private:
    QListWidget *m_list;
};

class ColorsDialog : public QDialog {
public:
    ColorsDialog(QWidget *parent, const ColorSet &colors);
    ColorSet result() const;

private:
    void paint(int cat);
    ColorSet m_colors;
    QVector<QCheckBox *> m_boxes;
    QVector<QPushButton *> m_buttons;
};

class AffinityDialog : public QDialog {
public:
    AffinityDialog(QWidget *parent, const QString &name, const QSet<int> &current, int ncpu);
    QVector<int> cpus() const;

private:
    QVector<QCheckBox *> m_boxes;
};
