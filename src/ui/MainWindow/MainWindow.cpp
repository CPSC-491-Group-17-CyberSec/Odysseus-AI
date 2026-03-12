#include "MainWindow.h"
#include "../ThreatCard/ThreatCard.h"
//#include "../../core/FileScanner.h"
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QWidget>
#include <QLabel>
#include <QFrame>
#include <QTableWidget>
#include <QHeaderView>
#include <QSpacerItem>
#include <QLineEdit>
#include <QComboBox>
#include <QIcon>
#include <QAction>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle("Odysseus-AI");
    resize(900, 600);

    auto* central = new QWidget(this);
    setCentralWidget(central);

    auto* layout = new QVBoxLayout(central);
    //simulateFileScan = new QPushButton("File scan", central);
    simulateThreatButton = new QPushButton("Simulate Threat Detection", central);
    layout->addWidget(simulateThreatButton);
   // layout->addWidget(simulateFileScan);

    // stretch so button stays at top
    layout->addStretch(1);

    connect(simulateThreatButton, &QPushButton::clicked,
            this, &MainWindow::onSimulateThreatClicked);
    //connect(simulateFileScan, &QPushButton::clicked, this, &MainWindow::onSimulateFileScan);
}


/* void MainWindow::onSimulateFileScan()
{
    FileScan("/home");
} */


void MainWindow::onSimulateThreatClicked()
{
    ThreatCard card(this);
    card.setSeverity(85);
    card.setSummary(
        "AI analysis indicates this file exhibits suspicious behavior:\n"
        "- Attempts to modify startup persistence\n"
        "- Drops an obfuscated payload\n"
        "- Connects to a known-bad domain\n"
    );
    card.setRemediation(
        "Recommended steps:\n"
        "1) Quarantine the file immediately.\n"
        "2) Run a full system scan.\n"
        "3) Review recent downloads and startup entries.\n"
        "4) If this is a work machine, notify your security team."
    );

    card.exec(); // modal popup
}

void MainWindow::loadTestData()
{
    addThreatEntry("🔴 Critical", "CVE-2025-1001", "Microsoft", "3/01/2026", "Active");
    addThreatEntry("🟡 Medium", "CVE-2025-2005", "Cisco", "2/15/2026", "Analyzing");
    addThreatEntry("🟢 Low", "CVE-2025-3002", "Oracle", "2/20/2026", "Active");
    addThreatEntry("🟢 Low", "CVE-2025-4009", "Microsoft", "1/12/2026", "Resolved");
    addThreatEntry("🔴 Critical", "Ransomware.Locky", "Unknown", "3/10/2026", "Quarantined");
}

void MainWindow::onFilterOrSearchChanged()
{
    QString searchText = searchInput->text().toLower();
    QString severityText = severityFilter->currentText();
    
    bool showAllSeverities = (severityText == "All Severities");

    for (int row = 0; row < threatTable->rowCount(); ++row) {
        bool matchSearch = false;
        bool matchSeverity = false;

        QString rowSeverity = threatTable->item(row, 0)->text();
        if (showAllSeverities || rowSeverity.contains(severityText)) {
            matchSeverity = true;
        }

        if (searchText.isEmpty()) {
            matchSearch = true;
        } else {
            for (int col = 0; col < threatTable->columnCount(); ++col) {
                if (threatTable->item(row, col)->text().toLower().contains(searchText)) {
                    matchSearch = true;
                    break;
                }
            }
        }

        threatTable->setRowHidden(row, !(matchSearch && matchSeverity));
    }
}

void MainWindow::onThreatDoubleClicked(int row, int /*column*/)
{
    // Extract data from the clicked row (Column 1 is the Name)
    QString threatName = threatTable->item(row, 1)->text();
    QString vendor = threatTable->item(row, 2)->text();
    
    detailsTitleLabel->setText(threatName);
    
    // Set Sample Content based on the row clicked
    detailsDescLabel->setText(
        "<b>Description:</b><br>"
        "A vulnerability or active threat associated with " + vendor + ". "
        "This entity was recently flagged during continuous monitoring. Further analysis is required to determine the exact blast radius within the network."
    );
    
    detailsAILabel->setText(
        "<b>AI Summary:</b><br>"
        "Odysseus AI has detected anomalous behavior matching known exploit patterns for " + threatName + ". "
        "The file/process attempted to modify startup registry keys and drop an obfuscated payload into a temporary directory. "
        "Recommended action is to isolate the affected subnet and apply the latest vendor patches."
    );
    
    detailsMitreLabel->setText(
        "<b>MITRE Technique:</b><br>"
        "<span style='background-color:#E6F3F5; padding:4px 8px; border-radius:4px;'>T1059 - Command and Scripting Interpreter</span>"
    );
    
    // Show the panel, layout automatically shrinks the left side
    detailsPanel->setVisible(true);
}

void MainWindow::onCloseDetailsClicked()
{
    // Hide the panel, layout automatically expands the left side back to full width
    detailsPanel->setVisible(false);
}

void MainWindow::onSimulateThreatClicked()
{
    ThreatCard card(this);
    card.setSeverity(85);
    card.setSummary(
        "AI analysis indicates this file exhibits suspicious behavior:\n"
        "- Attempts to modify startup persistence\n"
        "- Drops an obfuscated payload\n"
        "- Connects to a known-bad domain\n"
    );
    card.setRemediation(
        "Recommended steps:\n"
        "1) Quarantine the file immediately.\n"
        "2) Run a full system scan.\n"
        "3) Review recent downloads and startup entries.\n"
        "4) If this is a work machine, notify your security team."
    );

    card.exec();
}