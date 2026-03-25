#include "MainWindow.h"
#include "../../core/FileScanner.h"
#include "../../db/ScanDatabase.h"
#include "../ThreatCard/ThreatCard.h"

#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QWidget>
#include <QLabel>
#include <QFrame>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QSpacerItem>
#include <QLineEdit>
#include <QComboBox>
#include <QIcon>
#include <QListWidget>
#include <QListWidgetItem>
#include <QProgressBar>
#include <QTimer>
#include <QStandardPaths>
#include <QDir>
#include <QScrollArea>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QUrl>
#include <QUrlQuery>
#include <QDateTime>
#include <QFont>
#include <QBrush>
#include <utility>
#include <QStorageInfo>
#include <QResizeEvent>

// ============================================================================
// Helpers
// ============================================================================
QString MainWindow::formatElapsed(int secs)
{
    return QString("%1:%2")
        .arg(secs / 60, 2, 10, QChar('0'))
        .arg(secs % 60, 2, 10, QChar('0'));
}

static QString formatBytes(qint64 bytes)
{
    if (bytes >= 1LL << 30)
        return QString::number(bytes / double(1LL << 30), 'f', 1) + " GB";
    if (bytes >= 1LL << 20)
        return QString::number(bytes / double(1LL << 20), 'f', 1) + " MB";
    return QString::number(bytes / double(1LL << 10), 'f', 1) + " KB";
}

// ============================================================================
// Constructor
// ============================================================================
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle("Odysseus Threat Dashboard");
    resize(1100, 680);

    setupUi();

    // Existing connections
    connect(runScanButton,  &QPushButton::clicked,
            this,           &MainWindow::onRunScanClicked);
    connect(historyButton,  &QPushButton::clicked,
            this,           &MainWindow::onHistoryClicked);
    connect(searchInput,    &QLineEdit::textChanged,
            this,           &MainWindow::onFilterOrSearchChanged);
    connect(severityFilter, &QComboBox::currentTextChanged,
            this,           &MainWindow::onFilterOrSearchChanged);

    // Scan-type overlay (must be created after setupUi so the window has a size)
    m_scanOverlay = new ScanTypeOverlay(this);
    connect(m_scanOverlay, &ScanTypeOverlay::fullScanRequested,
            this,          &MainWindow::onFullScanRequested);
    connect(m_scanOverlay, &ScanTypeOverlay::partialScanRequested,
            this,          &MainWindow::onPartialScanRequested);

    // Scanner
    m_scanner = new FileScanner(this);
    connect(m_scanner, &FileScanner::scanningPath,
            this,      &MainWindow::onScanningPath);
    connect(m_scanner, &FileScanner::progressUpdated,
            this,      &MainWindow::onProgressUpdated);
    connect(m_scanner, &FileScanner::suspiciousFileFound,
            this,      &MainWindow::onSuspiciousFileFound);
    connect(m_scanner, &FileScanner::scanFinished,
            this,      &MainWindow::onScanFinished);
    connect(m_scanner, &FileScanner::scanError,
            this,      &MainWindow::onScanError);

    // Timer
    m_scanTimer = new QTimer(this);
    m_scanTimer->setInterval(1000);
    connect(m_scanTimer, &QTimer::timeout, this, &MainWindow::onScanTimerTick);

    // Network (CVE lookup)
    m_nam = new QNetworkAccessManager(this);
    connect(m_nam, &QNetworkAccessManager::finished,
            this,  &MainWindow::onCveLookupReply);

    // Database
    m_db = new ScanDatabase(this);
    connect(m_db, &ScanDatabase::recordSaved,
            this, &MainWindow::onDbRecordSaved);
    connect(m_db, &ScanDatabase::databaseError,
            this, [](const QString& msg){ qWarning() << "[DB ERROR]" << msg; });

    // Wire scanner cache signal → DB flush
    connect(m_scanner, &FileScanner::cacheUpdateReady,
            this,      &MainWindow::onCacheUpdateReady);

    // Pre-load persisted scan history from SQLite (newest-first)
    m_history = m_db->loadAllScanRecords();
    for (const ScanRecord& r : m_history) {
        QString label = QString("[%1]  %2 suspicious / %3 total  (%4)")
            .arg(r.timestamp.toString("yyyy-MM-dd hh:mm:ss"))
            .arg(r.suspiciousCount)
            .arg(r.totalScanned)
            .arg(formatElapsed(r.elapsedSeconds));
        auto* hi = new QListWidgetItem(label);
        hi->setForeground(QBrush(r.suspiciousCount > 0
                                 ? QColor("#B71C1C") : QColor("#2E7D32")));
        historyList->addItem(hi);
    }
}

MainWindow::~MainWindow()
{
    if (m_scanner)
        m_scanner->cancelScan();
}

void MainWindow::resizeEvent(QResizeEvent* e)
{
    QMainWindow::resizeEvent(e);
    if (m_scanOverlay)
        m_scanOverlay->setGeometry(rect());
}

// ============================================================================
// setupUi
// ============================================================================
void MainWindow::setupUi()
{
    auto* central = new QWidget(this);
    central->setStyleSheet(
        "QWidget { background-color: #F8F9FA; color: #000000;"
        " font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',"
        " Roboto, Helvetica, Arial, sans-serif; }"
    );
    setCentralWidget(central);

    auto* mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(30, 20, 30, 30);
    mainLayout->setSpacing(25);

    // =========================================================================
    // HEADER
    // =========================================================================
    auto* headerLayout = new QHBoxLayout();

    auto* logoLabel = new QLabel("[ O ]");
    logoLabel->setStyleSheet("font-size: 20px; font-weight: bold; color: #1a1aff; letter-spacing: 2px;");

    auto* titleLabel = new QLabel("<b>Odysseus</b> Threat Dashboard");
    titleLabel->setStyleSheet("font-size: 26px; color: #000000;");

    auto* headerSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    // History button
    historyButton = new QPushButton("History");
    historyButton->setCursor(Qt::PointingHandCursor);
    historyButton->setStyleSheet(
        "QPushButton { background-color: #555; color: white; border-radius: 15px;"
        " padding: 8px 20px; font-weight: bold; font-size: 13px; }"
        "QPushButton:hover { background-color: #333; }"
    );

    runScanButton = new QPushButton("Run Scan");
    runScanButton->setCursor(Qt::PointingHandCursor);
    runScanButton->setStyleSheet(
        "QPushButton { background-color: #1A1AEE; color: white; border-radius: 15px;"
        " padding: 8px 25px; font-weight: bold; font-size: 14px; }"
        "QPushButton:hover { background-color: #0000CC; }"
    );

    headerLayout->addWidget(logoLabel);
    headerLayout->addWidget(titleLabel);
    headerLayout->addSpacerItem(headerSpacer);
    headerLayout->addWidget(historyButton);
    headerLayout->addSpacing(10);
    headerLayout->addWidget(runScanButton);
    mainLayout->addLayout(headerLayout);

    // =========================================================================
    // MAIN CONTENT SPLIT
    // =========================================================================
    auto* contentLayout = new QHBoxLayout();
    mainLayout->addLayout(contentLayout, 1);

    // -- LEFT CONTAINER --
    auto* leftContainer = new QWidget();
    auto* leftLayout    = new QVBoxLayout(leftContainer);
    leftLayout->setContentsMargins(0, 0, 0, 0);
    leftLayout->setSpacing(25);
    contentLayout->addWidget(leftContainer, 5);

    // 1. STATS PANEL (unchanged)
    auto* statsFrame = new QFrame();
    statsFrame->setStyleSheet("QFrame { background-color: #E6F3F5; border-radius: 15px; color: #000000; }");
    auto* statsLayout = new QHBoxLayout(statsFrame);
    statsLayout->setContentsMargins(25, 25, 25, 25);

    auto* statsLeftLayout   = new QVBoxLayout();
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
    auto* barsLayout  = new QHBoxLayout();
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
    leftLayout->addWidget(statsFrame);

    // 2. SEARCH & FILTER
    auto* controlsLayout = new QHBoxLayout();

    searchInput = new QLineEdit();
    searchInput->setPlaceholderText("Search by keyword, CVE, or vendor...");
    QIcon searchIcon(":/icons/search.png");
    searchInput->addAction(searchIcon, QLineEdit::LeadingPosition);
    searchInput->setStyleSheet(
        "QLineEdit { padding: 10px; border-radius: 8px; border: 1px solid #CCC;"
        " font-size: 14px; background-color: #FFFFFF; color: #000000; }"
    );

    severityFilter = new QComboBox();
    severityFilter->addItems({"All Severities", "Critical", "High", "Medium", "Low"});
    severityFilter->setStyleSheet(
        "QComboBox { padding: 10px; border-radius: 8px; border: 1px solid #CCC;"
        " font-size: 14px; background-color: #FFFFFF; color: #000000; min-width: 150px; }"
        "QComboBox QAbstractItemView { color: #000000; background-color: #FFFFFF; }"
    );

    controlsLayout->addWidget(searchInput, 1);
    controlsLayout->addWidget(severityFilter);
    leftLayout->addLayout(controlsLayout);

    // 3. TABLE PANEL
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
    threatTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    threatTable->setShowGrid(false);
    threatTable->setSortingEnabled(true);
    threatTable->setStyleSheet(
        "QTableWidget { background-color: transparent; border: none; padding: 10px; color: #000000; }"
        "QHeaderView::section { background-color: transparent; font-size: 15px; font-weight: bold;"
        " border: none; border-bottom: 1px solid #000; padding: 10px 5px; color: #000000; }"
        "QTableWidget::item { border-bottom: 1px solid #CCC; padding: 8px 5px; color: #000000; }"
    );
    tableLayout->addWidget(threatTable);
    leftLayout->addWidget(tableFrame, 1);

    connect(threatTable, &QTableWidget::cellDoubleClicked,
            this,        &MainWindow::onThreatDoubleClicked);

    // =========================================================================
    // RIGHT-SIDE PANELS  (all in same contentLayout slot, mutually exclusive)
    // =========================================================================

    // ---- A. Threat-details panel (existing) ----
    detailsPanel = new QFrame();
    detailsPanel->setStyleSheet("QFrame { background-color: #F1F0EE; border-radius: 15px; color: #000000; }");
    auto* detailsLayout = new QVBoxLayout(detailsPanel);
    detailsLayout->setContentsMargins(25, 25, 25, 25);
    detailsLayout->setSpacing(20);

    auto* detailsHeaderLayout = new QHBoxLayout();
    detailsTitleLabel = new QLabel("Threat Details");
    detailsTitleLabel->setStyleSheet("font-size: 22px; font-weight: bold; color: #000000;");

    auto* closeDetailsButton = new QPushButton("✕");
    closeDetailsButton->setFixedSize(30, 30);
    closeDetailsButton->setCursor(Qt::PointingHandCursor);
    closeDetailsButton->setStyleSheet(
        "QPushButton { background-color: #E0E0E0; border-radius: 15px; font-weight: bold; border: none; }"
        "QPushButton:hover { background-color: #FF6B6B; color: white; }"
    );
    detailsHeaderLayout->addWidget(detailsTitleLabel);
    detailsHeaderLayout->addStretch();
    detailsHeaderLayout->addWidget(closeDetailsButton);
    detailsLayout->addLayout(detailsHeaderLayout);

    detailsDescLabel = new QLabel();
    detailsDescLabel->setWordWrap(true);
    detailsDescLabel->setStyleSheet("font-size: 14px; color: #333;");
    detailsLayout->addWidget(detailsDescLabel);

    detailsAILabel = new QLabel();
    detailsAILabel->setWordWrap(true);
    detailsAILabel->setStyleSheet("font-size: 14px; color: #333;");
    detailsLayout->addWidget(detailsAILabel);

    detailsMitreLabel = new QLabel();
    detailsMitreLabel->setWordWrap(true);
    detailsMitreLabel->setStyleSheet("font-size: 14px; color: #333; margin-top: 10px;");
    detailsLayout->addWidget(detailsMitreLabel);
    detailsLayout->addStretch(1);

    contentLayout->addWidget(detailsPanel, 3);
    detailsPanel->setVisible(false);

    connect(closeDetailsButton, &QPushButton::clicked,
            this,               &MainWindow::onCloseDetailsClicked);

    // ---- B. Scan-results panel ----
    scanResultsPanel = new QFrame();
    scanResultsPanel->setStyleSheet(
        "QFrame { background-color: #F1F0EE; border-radius: 15px; color: #000000; }"
    );
    auto* scanLayout = new QVBoxLayout(scanResultsPanel);
    scanLayout->setContentsMargins(25, 25, 25, 25);
    scanLayout->setSpacing(10);

    auto* scanHeaderLayout = new QHBoxLayout();
    auto* scanTitleLabel   = new QLabel("Scan Results");
    scanTitleLabel->setStyleSheet("font-size: 20px; font-weight: bold; color: #000000;");

    closeScanButton = new QPushButton("✕");
    closeScanButton->setFixedSize(30, 30);
    closeScanButton->setCursor(Qt::PointingHandCursor);
    closeScanButton->setStyleSheet(
        "QPushButton { background-color: #E0E0E0; border-radius: 15px; font-weight: bold; border: none; }"
        "QPushButton:hover { background-color: #FF6B6B; color: white; }"
    );
    scanHeaderLayout->addWidget(scanTitleLabel);
    scanHeaderLayout->addStretch();
    scanHeaderLayout->addWidget(closeScanButton);
    scanLayout->addLayout(scanHeaderLayout);

    scanStatusLabel = new QLabel("Initialising scan…");
    scanStatusLabel->setStyleSheet("font-size: 13px; font-weight: bold; color: #1A1AEE;");
    scanLayout->addWidget(scanStatusLabel);

    // Progress bar – linear fill, blue-green gradient
    scanProgressBar = new QProgressBar();
    scanProgressBar->setRange(0, 100);
    scanProgressBar->setValue(0);
    scanProgressBar->setTextVisible(false);
    scanProgressBar->setFixedHeight(10);
    scanProgressBar->setStyleSheet(
        "QProgressBar {"
        "  border-radius: 5px;"
        "  background-color: #D0EDE8;"
        "  border: none;"
        "}"
        "QProgressBar::chunk {"
        "  border-radius: 5px;"
        "  background: qlineargradient(x1:0, y1:0, x2:1, y2:0,"
        "    stop:0 #00C9A7, stop:1 #0099CC);"
        "}"
    );
    scanLayout->addWidget(scanProgressBar);

    auto* timerRow = new QHBoxLayout();
    scanStorageLabel = new QLabel("Storage: —");
    scanStorageLabel->setStyleSheet("font-size: 11px; color: #555;");
    scanElapsedLabel = new QLabel("Elapsed: 00:00");
    scanElapsedLabel->setStyleSheet("font-size: 11px; color: #555;");
    timerRow->addWidget(scanStorageLabel);
    timerRow->addStretch();
    timerRow->addWidget(scanElapsedLabel);
    scanLayout->addLayout(timerRow);

    scanPathLabel = new QLabel();
    scanPathLabel->setStyleSheet("font-size: 10px; color: #888;");
    scanPathLabel->setWordWrap(true);
    scanPathLabel->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Maximum);
    scanLayout->addWidget(scanPathLabel);

    scanResultsList = new QListWidget();
    scanResultsList->setStyleSheet(
        "QListWidget { background-color: #FFFFFF; border-radius: 8px; border: 1px solid #DDD;"
        " font-size: 11px; color: #000000; }"
        "QListWidget::item { padding: 5px 8px; border-bottom: 1px solid #EEE; }"
        "QListWidget::item:selected { background-color: #E6F3F5; }"
        "QListWidget::item:hover { background-color: #F5F5F5; }"
    );
    scanResultsList->setWordWrap(true);
    scanLayout->addWidget(scanResultsList, 1);

    scanSummaryLabel = new QLabel("Waiting for scan…");
    scanSummaryLabel->setStyleSheet("font-size: 11px; color: #555; font-style: italic;");
    scanLayout->addWidget(scanSummaryLabel);

    contentLayout->addWidget(scanResultsPanel, 3);
    scanResultsPanel->setVisible(false);

    connect(closeScanButton, &QPushButton::clicked,
            this,            &MainWindow::onCloseScanResultsClicked);

    // ---- C. History list panel ----
    historyPanel = new QFrame();
    historyPanel->setStyleSheet("QFrame { background-color: #F1F0EE; border-radius: 15px; color: #000000; }");
    auto* histLayout = new QVBoxLayout(historyPanel);
    histLayout->setContentsMargins(25, 25, 25, 25);
    histLayout->setSpacing(12);

    auto* histHeaderRow = new QHBoxLayout();
    auto* histTitle     = new QLabel("Scan History");
    histTitle->setStyleSheet("font-size: 20px; font-weight: bold;");

    closeHistoryButton = new QPushButton("✕");
    closeHistoryButton->setFixedSize(30, 30);
    closeHistoryButton->setCursor(Qt::PointingHandCursor);
    closeHistoryButton->setStyleSheet(
        "QPushButton { background-color: #E0E0E0; border-radius: 15px; font-weight: bold; border: none; }"
        "QPushButton:hover { background-color: #FF6B6B; color: white; }"
    );
    histHeaderRow->addWidget(histTitle);
    histHeaderRow->addStretch();
    histHeaderRow->addWidget(closeHistoryButton);
    histLayout->addLayout(histHeaderRow);

    auto* histHint = new QLabel("Click an entry to view details.");
    histHint->setStyleSheet("font-size: 11px; color: #888; font-style: italic;");
    histLayout->addWidget(histHint);

    historyList = new QListWidget();
    historyList->setStyleSheet(
        "QListWidget { background-color: #FFFFFF; border-radius: 8px; border: 1px solid #DDD;"
        " font-size: 12px; color: #000000; }"
        "QListWidget::item { padding: 8px; border-bottom: 1px solid #EEE; }"
        "QListWidget::item:selected { background-color: #E6F3F5; }"
        "QListWidget::item:hover { background-color: #F5F5F5; }"
    );
    histLayout->addWidget(historyList, 1);

    contentLayout->addWidget(historyPanel, 3);
    historyPanel->setVisible(false);

    connect(closeHistoryButton, &QPushButton::clicked,
            this, &MainWindow::onCloseHistoryClicked);
    connect(historyList, &QListWidget::itemClicked,
            this, &MainWindow::onHistoryItemClicked);

    // ---- D. History detail panel ----
    historyDetailPanel = new QFrame();
    historyDetailPanel->setStyleSheet(
        "QFrame { background-color: #F1F0EE; border-radius: 15px; color: #000000; }"
    );
    auto* hdLayout = new QVBoxLayout(historyDetailPanel);
    hdLayout->setContentsMargins(25, 25, 25, 25);
    hdLayout->setSpacing(12);

    auto* hdHeaderRow = new QHBoxLayout();
    histDetailTitleLabel = new QLabel("Scan Detail");
    histDetailTitleLabel->setStyleSheet("font-size: 18px; font-weight: bold;");

    closeHistoryDetailButton = new QPushButton("✕");
    closeHistoryDetailButton->setFixedSize(30, 30);
    closeHistoryDetailButton->setCursor(Qt::PointingHandCursor);
    closeHistoryDetailButton->setStyleSheet(
        "QPushButton { background-color: #E0E0E0; border-radius: 15px; font-weight: bold; border: none; }"
        "QPushButton:hover { background-color: #FF6B6B; color: white; }"
    );
    auto* backToHistBtn = new QPushButton("← Back");
    backToHistBtn->setCursor(Qt::PointingHandCursor);
    backToHistBtn->setStyleSheet(
        "QPushButton { background-color: transparent; color: #1A1AEE; border: none;"
        " font-size: 12px; font-weight: bold; }"
        "QPushButton:hover { color: #0000CC; }"
    );

    hdHeaderRow->addWidget(backToHistBtn);
    hdHeaderRow->addStretch();
    hdHeaderRow->addWidget(histDetailTitleLabel);
    hdHeaderRow->addStretch();
    hdHeaderRow->addWidget(closeHistoryDetailButton);
    hdLayout->addLayout(hdHeaderRow);

    histDetailSummaryLabel = new QLabel();
    histDetailSummaryLabel->setWordWrap(true);
    histDetailSummaryLabel->setStyleSheet("font-size: 12px; color: #444; padding: 8px;"
        " background-color: #E6F3F5; border-radius: 8px;");
    hdLayout->addWidget(histDetailSummaryLabel);

    histDetailFilesList = new QListWidget();
    histDetailFilesList->setStyleSheet(
        "QListWidget { background-color: #FFFFFF; border-radius: 8px; border: 1px solid #DDD;"
        " font-size: 11px; color: #000000; }"
        "QListWidget::item { padding: 5px 8px; border-bottom: 1px solid #EEE; }"
        "QListWidget::item:selected { background-color: #E6F3F5; }"
    );
    histDetailFilesList->setWordWrap(true);
    hdLayout->addWidget(histDetailFilesList, 1);

    contentLayout->addWidget(historyDetailPanel, 3);
    historyDetailPanel->setVisible(false);

    connect(closeHistoryDetailButton, &QPushButton::clicked,
            this, &MainWindow::onCloseHistoryClicked);
    connect(backToHistBtn, &QPushButton::clicked,
            this, &MainWindow::onHistoryClicked);
}

// ============================================================================
// showPanel
// ============================================================================
void MainWindow::showPanel(ActivePanel panel)
{
    m_activePanel = panel;
    detailsPanel->setVisible(panel       == ActivePanel::ThreatDetails);
    scanResultsPanel->setVisible(panel   == ActivePanel::ScanResults);
    historyPanel->setVisible(panel       == ActivePanel::History);
    historyDetailPanel->setVisible(panel == ActivePanel::HistoryDetail);
}

// ============================================================================
// addThreatEntry / loadTestData (unchanged)
// ============================================================================
void MainWindow::addThreatEntry(const QString& severity, const QString& name,
                                 const QString& vendor,   const QString& date,
                                 const QString& status)
{
    threatTable->setSortingEnabled(false);
    int row = threatTable->rowCount();
    threatTable->insertRow(row);
    QStringList cols = {severity, name, vendor, date, status};
    for (int i = 0; i < cols.size(); ++i) {
        auto* item = new QTableWidgetItem(cols[i]);
        item->setForeground(QBrush(Qt::black));
        threatTable->setItem(row, i, item);
    }
    if (severity.contains("Critical"))
        threatTable->item(row, 0)->setFont(QFont("Arial", 11, QFont::Bold));
    threatTable->resizeRowsToContents();
    threatTable->setSortingEnabled(true);
}

void MainWindow::loadTestData()
{
    // Table is populated by live scan results only
}

// ============================================================================
// addScanFindingToTable
// ============================================================================
void MainWindow::addScanFindingToTable(const SuspiciousFile& sf)
{
    threatTable->setSortingEnabled(false);
    int row = threatTable->rowCount();
    threatTable->insertRow(row);

    // Severity column – CVE-confirmed score takes precedence; category-derived is fallback
    QString sevText;
    QColor  sevColor;
    bool    cveConfirmed = !sf.cveSeverity.isEmpty();

    auto scoreStr = [&]() -> QString {
        return (sf.cveScore > 0.0f)
            ? QString(" (%1)").arg(double(sf.cveScore), 0, 'f', 1)
            : QString();
    };

    if (sf.cveSeverity == "CRITICAL") {
        sevText  = "Critical" + scoreStr(); sevColor = QColor("#C62828");
    } else if (sf.cveSeverity == "HIGH") {
        sevText  = "High" + scoreStr();     sevColor = QColor("#E65100");
    } else if (sf.cveSeverity == "MEDIUM") {
        sevText  = "Medium" + scoreStr();   sevColor = QColor("#F57F17");
    } else if (sf.cveSeverity == "LOW") {
        sevText  = "Low" + scoreStr();      sevColor = QColor("#2E7D32");
    } else {
        // No CVE – derive severity from detection category
        cveConfirmed = false;
        if (sf.category.contains("Known Malware") || sf.category.contains("PE Binary") ||
            sf.category.contains("ELF Binary")    || sf.category.contains("Mach-O")) {
            sevText = "Critical"; sevColor = QColor("#C62828");
        } else if (sf.category.contains("High-Risk") || sf.category.contains("Persistence") ||
                   sf.category.contains("Temp")) {
            sevText = "High";     sevColor = QColor("#E65100");
        } else {
            sevText = "Medium";   sevColor = QColor("#F57F17");
        }
    }
    Q_UNUSED(cveConfirmed)

    // Name column: CVE ID if we have one, otherwise filename
    QString nameText = sf.cveId.isEmpty() ? sf.fileName : sf.cveId;

    // Vendor: derive from category tag
    QString vendorText = sf.cveSummary.isEmpty() ? sf.category : "NVD";

    QString dateText = sf.lastModified.toString("M/dd/yyyy");

    QStringList cols = {sevText, nameText, vendorText, dateText, "Detected"};
    for (int i = 0; i < cols.size(); ++i) {
        auto* item = new QTableWidgetItem(cols[i]);
        item->setForeground(QBrush(i == 0 ? sevColor : Qt::black));
        if (i == 0) item->setFont(QFont("", -1, QFont::Bold));
        // Store full path in UserRole for the detail popup
        item->setData(Qt::UserRole,     sf.filePath);
        item->setData(Qt::UserRole + 1, sf.reason);
        item->setData(Qt::UserRole + 2, sf.cveId);
        item->setData(Qt::UserRole + 3, sf.cveSummary);
        threatTable->setItem(row, i, item);
    }

    threatTable->resizeRowsToContents();
    threatTable->setSortingEnabled(true);
}

// ============================================================================
// CVE lookup via NVD REST API 2.0
// ============================================================================
void MainWindow::lookupCveForFinding(int idx)
{
    if (idx < 0 || idx >= m_findings.size())
        return;

    const SuspiciousFile& sf = m_findings[idx];

    // Build a keyword query from the filename stem (strip extension)
    QString keyword = QFileInfo(sf.fileName).baseName();
    if (keyword.length() < 3) {
        // Too short to yield useful results – skip
        addScanFindingToTable(m_findings[idx]);
        return;
    }

    QUrl url("https://services.nvd.nist.gov/rest/json/cves/2.0");
    QUrlQuery q;
    q.addQueryItem("keywordSearch", keyword);
    q.addQueryItem("resultsPerPage", "1");
    url.setQuery(q);

    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::UserAgentHeader,
                  "Odysseus-Dashboard/1.0 (contact@example.com)");
    req.setAttribute(QNetworkRequest::User, idx);   // store index so we can match reply

    ++m_pendingCveQueries;
    m_nam->get(req);
}

void MainWindow::onCveLookupReply(QNetworkReply* reply)
{
    --m_pendingCveQueries;
    reply->deleteLater();

    int idx = reply->request().attribute(QNetworkRequest::User).toInt();
    if (idx < 0 || idx >= m_findings.size())
        return;

    SuspiciousFile& sf = m_findings[idx];

    if (reply->error() == QNetworkReply::NoError) {
        QByteArray data = reply->readAll();
        QJsonDocument doc = QJsonDocument::fromJson(data);
        QJsonObject root  = doc.object();
        QJsonArray  vulns = root.value("vulnerabilities").toArray();

        if (!vulns.isEmpty()) {
            QJsonObject cveNode = vulns[0].toObject().value("cve").toObject();
            sf.cveId = cveNode.value("id").toString();

            // Description (English preferred)
            QJsonArray descs = cveNode.value("descriptions").toArray();
            for (const QJsonValue& d : descs) {
                if (d.toObject().value("lang").toString() == "en") {
                    sf.cveSummary = d.toObject().value("value").toString();
                    if (sf.cveSummary.length() > 200)
                        sf.cveSummary = sf.cveSummary.left(197) + "…";
                    break;
                }
            }

            // CVSS severity + base score – try v3.1, v3.0, v2 in order
            QJsonObject metrics = cveNode.value("metrics").toObject();
            for (const QString& key : {"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"}) {
                QJsonArray arr = metrics.value(key).toArray();
                if (!arr.isEmpty()) {
                    QJsonObject cvssData = arr[0].toObject().value("cvssData").toObject();
                    sf.cveSeverity = cvssData.value("baseSeverity").toString().toUpper();
                    sf.cveScore    = float(cvssData.value("baseScore").toDouble(0.0));
                    break;
                }
            }
        }
    }

    // Always add to table (with or without CVE data)
    addScanFindingToTable(sf);
}

// ============================================================================
// EXISTING SLOTS (logic unchanged)
// ============================================================================
void MainWindow::onFilterOrSearchChanged()
{
    QString searchText   = searchInput->text().toLower();
    QString severityText = severityFilter->currentText();
    bool    showAll      = (severityText == "All Severities");

    for (int row = 0; row < threatTable->rowCount(); ++row) {
        bool matchSearch   = false;
        bool matchSeverity = false;

        if (showAll || threatTable->item(row, 0)->text().contains(severityText))
            matchSeverity = true;

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
    QString threatName = threatTable->item(row, 1)->text();
    QString vendor     = threatTable->item(row, 2)->text();

    // Check if this row has scan-finding data (UserRole set)
    QString filePath   = threatTable->item(row, 0)->data(Qt::UserRole).toString();
    QString reason     = threatTable->item(row, 0)->data(Qt::UserRole + 1).toString();
    QString cveId      = threatTable->item(row, 0)->data(Qt::UserRole + 2).toString();
    QString cveSummary = threatTable->item(row, 0)->data(Qt::UserRole + 3).toString();

    detailsTitleLabel->setText(threatName);

    if (!filePath.isEmpty()) {
        // Scan-derived entry
        detailsDescLabel->setText(
            "<b>File Path:</b><br>" + filePath + "<br><br>"
            "<b>Detection Reason:</b><br>" + reason
        );
        detailsAILabel->setText(
            "<b>CVE:</b> " + (cveId.isEmpty() ? "No matching CVE found" : cveId) + "<br><br>"
            + (cveSummary.isEmpty() ? "" : "<b>NVD Summary:</b><br>" + cveSummary)
        );
        detailsMitreLabel->setText(
            "<b>Vendor:</b> " + vendor + "<br>"
            "<b>Source:</b> <span style='background-color:#E6F3F5; padding:3px 6px;"
            " border-radius:4px;'>Odysseus File Scanner</span>"
        );
    } else {
        // Original static entry
        detailsDescLabel->setText(
            "<b>Description:</b><br>"
            "A vulnerability or active threat associated with " + vendor + ". "
            "This entity was recently flagged during continuous monitoring."
        );
        detailsAILabel->setText(
            "<b>AI Summary:</b><br>"
            "Odysseus AI detected anomalous behaviour matching known exploit patterns for " +
            threatName + ". Recommended action: isolate the affected subnet and apply patches."
        );
        detailsMitreLabel->setText(
            "<b>MITRE Technique:</b><br>"
            "<span style='background-color:#E6F3F5; padding:4px 8px; border-radius:4px;'>"
            "T1059 - Command and Scripting Interpreter</span>"
        );
    }

    showPanel(ActivePanel::ThreatDetails);
}

void MainWindow::onCloseDetailsClicked()
{
    showPanel(ActivePanel::None);
}

void MainWindow::onSimulateThreatClicked()
{
    ThreatCard card(this);
    card.setSeverity(85);
    card.setSummary(
        "AI analysis indicates this file exhibits suspicious behaviour:\n"
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

// ============================================================================
// SCAN SLOTS
// ============================================================================
void MainWindow::onRunScanClicked()
{
    if (m_scanner->isRunning()) {
        // Cancel the active scan
        m_scanTimer->stop();
        m_scanner->cancelScan();
        runScanButton->setText("Run Scan");
        runScanButton->setStyleSheet(
            "QPushButton { background-color: #1A1AEE; color: white; border-radius: 15px;"
            " padding: 8px 25px; font-weight: bold; font-size: 14px; }"
            "QPushButton:hover { background-color: #0000CC; }"
        );
        scanProgressBar->setValue(0);
        scanStatusLabel->setText("Scan cancelled.");
        scanStatusLabel->setStyleSheet("font-size: 13px; font-weight: bold; color: #888;");
        scanPathLabel->clear();
        return;
    }

    // Show the scan-type selection overlay
    m_scanOverlay->showOverlay();
}

void MainWindow::onFullScanRequested()
{
    QString rootPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation);
    if (rootPath.isEmpty())
        rootPath = QDir::rootPath();
    startScanForPath(rootPath);
}

void MainWindow::onPartialScanRequested(const QString& path)
{
    startScanForPath(path);
}

void MainWindow::startScanForPath(const QString& rootPath)
{
    // Reset state
    m_findings.clear();
    m_elapsedSeconds    = 0;
    m_cveQueryIndex     = 0;
    m_pendingCveQueries = 0;
    m_driveTotalBytes   = 0;

    scanResultsList->clear();
    scanSummaryLabel->setText("Scanning...");
    scanStatusLabel->setText("Scanning in progress...");
    scanStatusLabel->setStyleSheet("font-size: 13px; font-weight: bold; color: #1A1AEE;");
    scanElapsedLabel->setText("Elapsed: 00:00");
    scanStorageLabel->setText("Storage: —");
    scanPathLabel->clear();
    scanProgressBar->setValue(0);

    showPanel(ActivePanel::ScanResults);

    runScanButton->setText("Cancel Scan");
    runScanButton->setStyleSheet(
        "QPushButton { background-color: #CC2200; color: white; border-radius: 15px;"
        " padding: 8px 25px; font-weight: bold; font-size: 14px; }"
        "QPushButton:hover { background-color: #AA1100; }"
    );

    qDebug() << "=== Odysseus File Scan Started ===" << rootPath;
    m_scanTimer->start();

    // Capture total capacity of the drive being scanned
    QStorageInfo si(rootPath);
    m_driveTotalBytes = si.bytesTotal();
    if (m_driveTotalBytes > 0)
        scanStorageLabel->setText("Storage: 0 B / " + formatBytes(m_driveTotalBytes));

    // Load scan cache and pass it to the worker for incremental scanning.
    QHash<QString, QString> cache;
    if (m_db)
        cache = m_db->loadScanCache();
    m_scanner->startScan(rootPath, std::move(cache));
}

void MainWindow::onScanTimerTick()
{
    ++m_elapsedSeconds;
    scanElapsedLabel->setText("Elapsed: " + formatElapsed(m_elapsedSeconds));
}

void MainWindow::onScanningPath(const QString& path)
{
    QString display = path;
    if (display.length() > 72)
        display = "…" + display.right(69);
    scanPathLabel->setText(display);
}

void MainWindow::onProgressUpdated(int percent)
{
    // Simple clamped linear update – no jumping, bar only moves forward
    if (percent > scanProgressBar->value())
        scanProgressBar->setValue(percent);
}

void MainWindow::onSuspiciousFileFound(const SuspiciousFile& file)
{
    m_findings.append(file);

    qDebug() << "[SUSPICIOUS]" << file.category
             << "|" << file.filePath
             << "|" << file.reason;

    // Colour-code in scan panel list
    QString prefix = "[!]";
    QColor  bg     = QColor("#FFF8E1");
    if (file.category.contains("Known Malware") || file.category.contains("PE Binary") ||
        file.category.contains("ELF Binary")    || file.category.contains("Mach-O")) {
        prefix = "[CRIT]"; bg = QColor("#FDECEA");
    } else if (file.category.contains("High-Risk") || file.category.contains("Persistence") ||
               file.category.contains("Temp")) {
        prefix = "[HIGH]"; bg = QColor("#FFF3E0");
    } else if (file.category.contains("Suspicious Name") || file.category.contains("Double-Extension")) {
        prefix = "[MED]";  bg = QColor("#FFFDE7");
    }

    QString displayText = QString("%1 %2\n   %3\n   %4")
        .arg(prefix)
        .arg(file.fileName)
        .arg(file.category)
        .arg(file.filePath.length() > 60
             ? "..." + file.filePath.right(57)
             : file.filePath);

    auto* item = new QListWidgetItem(displayText, scanResultsList);
    item->setBackground(QBrush(bg));
    item->setToolTip(
        QString("Path: %1\nReason: %2\nSize: %3 bytes\nModified: %4")
            .arg(file.filePath)
            .arg(file.reason)
            .arg(file.sizeBytes)
            .arg(file.lastModified.toString(Qt::ISODate))
    );
    scanResultsList->scrollToBottom();

    scanSummaryLabel->setText(
        QString("%1 suspicious file(s) found so far…").arg(m_findings.size())
    );
}

void MainWindow::onScanFinished(int totalScanned, int suspiciousCount, int elapsedSeconds, qint64 bytesScanned)
{
    m_scanTimer->stop();

    runScanButton->setText("Run Scan");
    runScanButton->setStyleSheet(
        "QPushButton { background-color: #1A1AEE; color: white; border-radius: 15px;"
        " padding: 8px 25px; font-weight: bold; font-size: 14px; }"
        "QPushButton:hover { background-color: #0000CC; }"
    );

    scanProgressBar->setValue(100);
    scanElapsedLabel->setText("Elapsed: " + formatElapsed(elapsedSeconds));
    scanPathLabel->clear();

    // Update storage counter with final scanned bytes vs drive total
    if (m_driveTotalBytes > 0)
        scanStorageLabel->setText(
            "Storage: " + formatBytes(bytesScanned) + " / " + formatBytes(m_driveTotalBytes)
        );
    else
        scanStorageLabel->setText("Storage: " + formatBytes(bytesScanned));

    if (suspiciousCount == 0) {
        qDebug() << "Nothing to do";
        scanStatusLabel->setText("Scan complete — nothing suspicious found.");
        scanStatusLabel->setStyleSheet("font-size: 13px; font-weight: bold; color: #2E7D32;");

        auto* item = new QListWidgetItem(
            "Nothing to do — no suspicious files detected.", scanResultsList
        );
        item->setForeground(QBrush(QColor("#2E7D32")));

        scanSummaryLabel->setText(
            QString("Scanned %1 file(s) — all clear.").arg(totalScanned)
        );
    } else {
        qDebug() << "=== Scan Complete ===";
        qDebug() << "Total files scanned:" << totalScanned;
        qDebug() << "Suspicious files   :" << suspiciousCount;
        for (const SuspiciousFile& sf : m_findings)
            qDebug() << " " << sf.filePath << "->" << sf.category;

        scanStatusLabel->setText(
            QString("Scan complete — %1 suspicious file(s) found.").arg(suspiciousCount)
        );
        scanStatusLabel->setStyleSheet("font-size: 13px; font-weight: bold; color: #B71C1C;");

        scanSummaryLabel->setText(
            QString("Looking up CVEs for %1 finding(s)...").arg(suspiciousCount)
        );

        // Kick off CVE queries (rate-limited: one at a time via m_cveQueryIndex)
        // We launch them all; the NAM queues them internally.
        for (int i = 0; i < m_findings.size(); ++i)
            lookupCveForFinding(i);
    }

    // Save to history regardless
    ScanRecord record;
    record.timestamp       = QDateTime::currentDateTime();
    record.totalScanned    = totalScanned;
    record.suspiciousCount = suspiciousCount;
    record.elapsedSeconds  = elapsedSeconds;
    record.findings        = m_findings;   // snapshot (CVE fields may still be empty, ok)
    m_history.prepend(record);  // newest first; historyList is rebuilt on demand

    // Persist to SQLite (async – writer thread handles it)
    if (m_db) {
        m_db->saveScanRecord(record);
        // Prune stale cache entries every 5 scans to prevent unbounded growth
        ++m_scanCount;
        if (m_scanCount % 5 == 0)
            m_db->pruneStaleCache();
    }
}

void MainWindow::onScanError(const QString& message)
{
    m_scanTimer->stop();

    runScanButton->setText("Run Scan");
    runScanButton->setStyleSheet(
        "QPushButton { background-color: #1A1AEE; color: white; border-radius: 15px;"
        " padding: 8px 25px; font-weight: bold; font-size: 14px; }"
        "QPushButton:hover { background-color: #0000CC; }"
    );
    scanProgressBar->setValue(0);
    qDebug() << "[SCAN ERROR]" << message;
    scanStatusLabel->setText("Scan error: " + message);
    scanStatusLabel->setStyleSheet("font-size: 13px; font-weight: bold; color: #B71C1C;");
    scanPathLabel->clear();
    scanSummaryLabel->setText("Scan could not complete.");
}

void MainWindow::onCloseScanResultsClicked()
{
    showPanel(ActivePanel::None);
}

// ============================================================================
// HISTORY SLOTS
// ============================================================================
void MainWindow::onHistoryClicked()
{
    // Rebuild the list from m_history every time so stale placeholders never
    // appear alongside real entries after the first scan completes.
    historyList->clear();

    if (m_history.isEmpty()) {
        auto* placeholder = new QListWidgetItem("No scans have been run yet.");
        placeholder->setForeground(QBrush(QColor("#888")));
        historyList->addItem(placeholder);
    } else {
        for (const ScanRecord& r : m_history) {
            QString label = QString("[%1]  %2 suspicious / %3 total  (%4)")
                .arg(r.timestamp.toString("yyyy-MM-dd hh:mm:ss"))
                .arg(r.suspiciousCount)
                .arg(r.totalScanned)
                .arg(formatElapsed(r.elapsedSeconds));
            auto* item = new QListWidgetItem(label);
            item->setForeground(QBrush(
                r.suspiciousCount > 0 ? QColor("#B71C1C") : QColor("#2E7D32")
            ));
            historyList->addItem(item);
        }
    }

    showPanel(ActivePanel::History);
}

void MainWindow::onHistoryItemClicked(QListWidgetItem* item)
{
    int idx = historyList->row(item);
    if (idx < 0 || idx >= m_history.size())
        return;
    showHistoryDetail(m_history[idx]);
}

void MainWindow::onCloseHistoryClicked()
{
    showPanel(ActivePanel::None);
}

void MainWindow::showHistoryDetail(const ScanRecord& record)
{
    histDetailTitleLabel->setText(
        "Scan — " + record.timestamp.toString("yyyy-MM-dd hh:mm:ss")
    );

    histDetailSummaryLabel->setText(
        QString("Files scanned: %1\n"
                "Suspicious files: %2\n"
                "Duration: %3")
            .arg(record.totalScanned)
            .arg(record.suspiciousCount)
            .arg(formatElapsed(record.elapsedSeconds))
    );

    histDetailFilesList->clear();

    if (record.findings.isEmpty()) {
        auto* ok = new QListWidgetItem("Nothing to do — scan was clean.");
        ok->setForeground(QBrush(QColor("#2E7D32")));
        histDetailFilesList->addItem(ok);
    } else {
        for (const SuspiciousFile& sf : record.findings) {
            QString cveTag = sf.cveId.isEmpty()
                ? ""
                : QString("  [%1 – %2]").arg(sf.cveId, sf.cveSeverity);

            QString text = QString("• %1%2\n   %3\n   %4")
                .arg(sf.fileName)
                .arg(cveTag)
                .arg(sf.category)
                .arg(sf.filePath.length() > 65
                     ? "…" + sf.filePath.right(62)
                     : sf.filePath);

            auto* it = new QListWidgetItem(text, histDetailFilesList);

            QColor bg("#FFF8E1");
            if (sf.category.contains("Known Malware") || sf.category.contains("PE Binary") ||
                sf.category.contains("ELF Binary")    || sf.category.contains("Mach-O"))
                bg = QColor("#FDECEA");
            else if (sf.category.contains("High-Risk") || sf.category.contains("Persistence"))
                bg = QColor("#FFF3E0");

            it->setBackground(QBrush(bg));
            it->setToolTip("Reason: " + sf.reason
                + (sf.cveSummary.isEmpty() ? "" : "\n\nCVE Summary: " + sf.cveSummary));
        }
    }

    showPanel(ActivePanel::HistoryDetail);
}
// ============================================================================
// DATABASE SLOTS
// ============================================================================
void MainWindow::onDbRecordSaved(qint64 scanId)
{
    qDebug() << "[DB] Scan record saved, rowid =" << scanId;
}

void MainWindow::onCacheUpdateReady(const QVector<CacheEntry>& entries)
{
    // Received on UI thread via queued connection after scan finishes.
    // Hand off to the DB writer thread immediately – non-blocking.
    if (m_db)
        m_db->flushScanCache(entries);
    qDebug() << "[DB] Cache flush queued for" << entries.size() << "entries";
}