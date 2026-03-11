// MainWindow.h
#pragma once

#include <QMainWindow>
#include <QString>

class QPushButton;
class QTableWidget;
class QLineEdit;
class QComboBox;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

private slots:
    void onSimulateThreatClicked();
    void onFilterOrSearchChanged();

private:
    QPushButton* runScanButton;
    QTableWidget* threatTable;
    QLineEdit* searchInput;
    QComboBox* severityFilter;

    void setupUi();
    void loadTestData();
    void addThreatEntry(const QString& severity, const QString& name, 
                        const QString& vendor, const QString& date, 
                        const QString& status);
};