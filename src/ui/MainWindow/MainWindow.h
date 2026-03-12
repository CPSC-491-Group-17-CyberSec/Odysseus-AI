#pragma once

#include <QMainWindow>
#include <QString>

class QPushButton;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

private slots:
    void onSimulateThreatClicked();
    //void onSimulateFileScan();

private:
    QPushButton* simulateThreatButton;
   // QPushButton* simulateFileScan;
};