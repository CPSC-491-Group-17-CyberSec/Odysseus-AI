#include "MainWindow.h"
#include "../ThreatCard/ThreatCard.h"

#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle("Odysseus-AI");
    resize(900, 600);

    auto* central = new QWidget(this);
    setCentralWidget(central);

    auto* layout = new QVBoxLayout(central);

    simulateThreatButton = new QPushButton("Simulate Threat Detection", central);
    layout->addWidget(simulateThreatButton);

    // stretch so button stays at top
    layout->addStretch(1);

    connect(simulateThreatButton, &QPushButton::clicked,
            this, &MainWindow::onSimulateThreatClicked);
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

    card.exec(); // modal popup
}
