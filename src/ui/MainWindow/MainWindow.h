#pragma once

#include <QMainWindow>

class QPushButton;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

private slots:
    void onSimulateThreatClicked();

private:
    QPushButton* simulateThreatButton;
};
