#pragma once

#include <QMainWindow>
#include <QString>

class QPushButton;
class QTableWidget;
class QLineEdit;
class QComboBox;
class QFrame;
class QLabel;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

private slots:
    void onSimulateThreatClicked();
    void onFilterOrSearchChanged();
    void onThreatDoubleClicked(int row, int column); // Slot for opening details
    void onCloseDetailsClicked();                    // Slot for closing details

private:
    QPushButton* runScanButton;
    QTableWidget* threatTable;
    QLineEdit* searchInput;
    QComboBox* severityFilter;
    
    // Details Panel Elements
    QFrame* detailsPanel;
    QLabel* detailsTitleLabel;
    QLabel* detailsDescLabel;
    QLabel* detailsAILabel;
    QLabel* detailsMitreLabel;

    void setupUi();
    void loadTestData();
    void addThreatEntry(const QString& severity, const QString& name, 
                        const QString& vendor, const QString& date, 
                        const QString& status);
};