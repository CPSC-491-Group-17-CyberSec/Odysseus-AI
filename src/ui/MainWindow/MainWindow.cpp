// MainWindow.cpp
#include "MainWindow.h"
#include "../ThreatCard/ThreatCard.h"
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
    setWindowTitle("Odysseus Threat Dashboard");
    resize(1000, 650);

    setupUi();
    loadTestData();

    connect(runScanButton, &QPushButton::clicked, this, &MainWindow::onSimulateThreatClicked);
    connect(searchInput, &QLineEdit::textChanged, this, &MainWindow::onFilterOrSearchChanged);
    connect(severityFilter, &QComboBox::currentTextChanged, this, &MainWindow::onFilterOrSearchChanged);
}

void MainWindow::setupUi()
{
    auto* central = new QWidget(this);
    central->setStyleSheet("QWidget { background-color: #F8F9FA; color: #000000; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }");
    setCentralWidget(central);

    auto* mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(30, 20, 30, 30);
    mainLayout->setSpacing(25);

    // --- HEADER ---
    auto* headerLayout = new QHBoxLayout();
    
    auto* logoLabel = new QLabel("🛡️");
    logoLabel->setStyleSheet("font-size: 32px; color: #1a1aff;");
    
    auto* titleLabel = new QLabel("<b>Odysseus</b> Threat Dashboard");
    titleLabel->setStyleSheet("font-size: 26px; color: #000000;");
    
    auto* headerSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
    
    auto* userLabel = new QLabel("👤");
    userLabel->setStyleSheet("font-size: 24px; color: #888; margin-right: 15px;");
    
    runScanButton = new QPushButton("Run Scan");
    runScanButton->setCursor(Qt::PointingHandCursor);
    runScanButton->setStyleSheet(
        "QPushButton {"
        "  background-color: #1A1AEE;"
        "  color: white;"
        "  border-radius: 15px;"
        "  padding: 8px 25px;"
        "  font-weight: bold;"
        "  font-size: 14px;"
        "}"
        "QPushButton:hover { background-color: #0000CC; }"
    );
    
    headerLayout->addWidget(logoLabel);
    headerLayout->addWidget(titleLabel);
    headerLayout->addSpacerItem(headerSpacer);
    headerLayout->addWidget(userLabel);
    headerLayout->addWidget(runScanButton);
    
    mainLayout->addLayout(headerLayout);

    // --- STATS PANEL ---
    auto* statsFrame = new QFrame();
    statsFrame->setStyleSheet("QFrame { background-color: #E6F3F5; border-radius: 15px; color: #000000; }");
    auto* statsLayout = new QHBoxLayout(statsFrame);
    statsLayout->setContentsMargins(25, 25, 25, 25);
    
    auto* statsLeftLayout = new QVBoxLayout();
    auto* totalThreatsLabel = new QLabel("Total Active Threats");
    totalThreatsLabel->setStyleSheet("font-size: 24px; font-weight: bold;");
    auto* numberLabel = new QLabel("50");
    numberLabel->setStyleSheet("font-size: 72px; font-weight: bold; margin-top: -10px; margin-bottom: -10px;");
    auto* updatedLabel = new QLabel("Last updated 2 min ago <font color='#00DD00'>●</font>");
    updatedLabel->setStyleSheet("font-size: 12px; color: #666;");
    
    statsLeftLayout->addWidget(totalThreatsLabel);
    statsLeftLayout->addWidget(numberLabel);
    statsLeftLayout->addWidget(updatedLabel);
    statsLeftLayout->addStretch(1);
    
    auto* chartLayout = new QVBoxLayout();
    auto* barsLayout = new QHBoxLayout();
    barsLayout->setSpacing(5);
    barsLayout->setAlignment(Qt::AlignBottom | Qt::AlignRight);
    
    auto* bar1 = new QFrame(); bar1->setStyleSheet("background-color: #0000EE; border-radius: 0px;"); bar1->setFixedSize(30, 80);
    auto* bar2 = new QFrame(); bar2->setStyleSheet("background-color: #0000EE; border-radius: 0px;"); bar2->setFixedSize(30, 50);
    auto* bar3 = new QFrame(); bar3->setStyleSheet("background-color: #0000EE; border-radius: 0px;"); bar3->setFixedSize(30, 110);
    
    barsLayout->addWidget(bar1);
    barsLayout->addWidget(bar2);
    barsLayout->addWidget(bar3);
    
    auto* trendLabel = new QLabel("Threat Trend (24h)");
    trendLabel->setStyleSheet("font-size: 14px; font-weight: bold; margin-top: 10px;");
    trendLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    
    chartLayout->addStretch(1);
    chartLayout->addLayout(barsLayout);
    chartLayout->addWidget(trendLabel);
    
    statsLayout->addLayout(statsLeftLayout);
    statsLayout->addLayout(chartLayout);
    
    mainLayout->addWidget(statsFrame);

    // --- SEARCH AND FILTER CONTROLS ---
    auto* controlsLayout = new QHBoxLayout();
    
    searchInput = new QLineEdit();
    searchInput->setPlaceholderText("Search by keyword, CVE, or vendor...");
    
    // Use an action for the magnifying glass to keep it fixed on the left
    // Note: If you don't have a search.png in your resources, the icon won't appear, 
    // but it will no longer mess up the cursor text flow.
    QIcon searchIcon(":/icons/search.png"); 
    searchInput->addAction(searchIcon, QLineEdit::LeadingPosition);

    searchInput->setStyleSheet(
        "QLineEdit { "
        "  padding: 10px; "
        "  border-radius: 8px; "
        "  border: 1px solid #CCC; "
        "  font-size: 14px; "
        "  background-color: #FFFFFF; "
        "  color: #000000; " 
        "}"
    );
    
    severityFilter = new QComboBox();
    severityFilter->addItems({"All Severities", "Critical", "Medium", "Low"});
    severityFilter->setStyleSheet(
        "QComboBox { "
        "  padding: 10px; "
        "  border-radius: 8px; "
        "  border: 1px solid #CCC; "
        "  font-size: 14px; "
        "  background-color: #FFFFFF; "
        "  color: #000000; "
        "  min-width: 150px; "
        "}"
        "QComboBox QAbstractItemView { color: #000000; background-color: #FFFFFF; }"
    );
    
    controlsLayout->addWidget(searchInput, 1);
    controlsLayout->addWidget(severityFilter);
    mainLayout->addLayout(controlsLayout);

    // --- TABLE PANEL ---
    auto* tableFrame = new QFrame();
    tableFrame->setStyleSheet("QFrame { background-color: #F1F0EE; border-radius: 15px; }");
    auto* tableLayout = new QVBoxLayout(tableFrame);
    tableLayout->setContentsMargins(0, 0, 0, 0);

    threatTable = new QTableWidget(0, 5);
    threatTable->setHorizontalHeaderLabels({"Severity", "Name", "Vendor", "Published", "Status"});
    threatTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    threatTable->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    threatTable->verticalHeader()->setVisible(false);
    threatTable->setFocusPolicy(Qt::NoFocus);
    threatTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    threatTable->setShowGrid(false);
    threatTable->setSortingEnabled(true);
    threatTable->setStyleSheet(
        "QTableWidget { background-color: transparent; border: none; padding: 10px; color: #000000; }"
        "QHeaderView::section { "
        "  background-color: transparent; "
        "  font-size: 15px; "
        "  font-weight: bold; "
        "  border: none; "
        "  border-bottom: 1px solid #000; "
        "  padding: 10px 5px; "
        "  color: #000000; "
        "}"
        "QTableWidget::item { border-bottom: 1px solid #CCC; padding: 8px 5px; color: #000000; }"
    );
    
    tableLayout->addWidget(threatTable);
    mainLayout->addWidget(tableFrame, 1); 
}

void MainWindow::addThreatEntry(const QString& severity, const QString& name, const QString& vendor, const QString& date, const QString& status)
{
    threatTable->setSortingEnabled(false);
    
    int row = threatTable->rowCount();
    threatTable->insertRow(row);

    QStringList data = {severity, name, vendor, date, status};
    for(int i = 0; i < data.size(); ++i) {
        auto* item = new QTableWidgetItem(data[i]);
        item->setForeground(QBrush(Qt::black)); 
        threatTable->setItem(row, i, item);
    }

    if (severity.contains("Critical")) {
        threatTable->item(row, 0)->setFont(QFont("Arial", 11, QFont::Bold));
    }

    threatTable->resizeRowsToContents();
    threatTable->setSortingEnabled(true);
}

void MainWindow::loadTestData()
{
    addThreatEntry("🔴 Critical", "CVE-20251", "Microsoft", "1/12/2025", "Active");
    addThreatEntry("🟡 Medium", "CVE-20252", "Cisco", "1/05/2025", "Analyzing");
    addThreatEntry("🟢 Low", "CVE-20253", "Oracle", "1/11/2025", "Active");
    addThreatEntry("🟢 Low", "CVE-20254", "Microsoft", "1/12/2025", "Resolved");
    addThreatEntry("🔴 Critical", "Ransomware.Locky", "Unknown", "1/15/2025", "Quarantined");
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