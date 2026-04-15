#include "MainWindow.h"
#include "../../core/FileScanner.h"
#include "../../db/ScanDatabase.h"
#include "../ThreatCard/ThreatCard.h"
#include "ai/LLMExplainer.h"
#include "ai/FeatureExtractor.h"

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
#include <QDirIterator>
#include <QResizeEvent>
#include <QThread>

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
    connect(m_scanOverlay, &ScanTypeOverlay::resumeScanRequested,
            this,          &MainWindow::onResumeScanRequested);

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
        // Recompute per-category counts from findings
        int c = 0, s = 0, rv = 0;
        for (const SuspiciousFile& sf : r.findings) {
            QString cls = sf.classificationLevel.toUpper();
            if (cls == "CRITICAL")        ++c;
            else if (cls == "SUSPICIOUS") ++s;
            else                          ++rv;
        }
        QStringList cats;
        if (c > 0)  cats << QString("%1 crit").arg(c);
        if (s > 0)  cats << QString("%1 susp").arg(s);
        if (rv > 0) cats << QString("%1 review").arg(rv);
        QString buckets;
        if (cats.isEmpty() && r.suspiciousCount > 0)
            buckets = QString("%1 flagged").arg(r.suspiciousCount);
        else if (cats.isEmpty())
            buckets = "clean";
        else
            buckets = cats.join(", ");

        QString label = QString("[%1]  %2 / %3 total  (%4)")
            .arg(r.timestamp.toString("yyyy-MM-dd hh:mm:ss"))
            .arg(buckets)
            .arg(r.totalScanned)
            .arg(formatElapsed(r.elapsedSeconds));
        auto* hi = new QListWidgetItem(label);
        QColor color = QColor("#2E7D32");
        if (c > 0)       color = QColor("#B71C1C");
        else if (s > 0)  color = QColor("#E65100");
        else if (rv > 0) color = QColor("#F57F17");
        else if (r.suspiciousCount > 0) color = QColor("#B71C1C");
        hi->setForeground(QBrush(color));
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

    // 1. AI DASHBOARD STATS PANEL
    auto* statsFrame = new QFrame();
    statsFrame->setStyleSheet(
        "QFrame#aiDashboard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,"
        "  stop:0 #E8EAF6, stop:0.5 #E6F3F5, stop:1 #E8F5E9);"
        "  border-radius: 15px; color: #000000; }"
    );
    statsFrame->setObjectName("aiDashboard");
    auto* statsLayout = new QHBoxLayout(statsFrame);
    statsLayout->setContentsMargins(25, 20, 25, 20);
    statsLayout->setSpacing(20);

    // ── Left: AI badge + total findings ──
    auto* statsLeftLayout = new QVBoxLayout();
    statsLeftLayout->setSpacing(4);

    auto* aiBadgeRow = new QHBoxLayout();
    auto* aiBadge = new QLabel("\xF0\x9F\xA7\xA0");   // brain emoji
    aiBadge->setStyleSheet("font-size: 18px;");
    auto* aiTitle = new QLabel("AI Threat Analysis");
    aiTitle->setStyleSheet("font-size: 20px; font-weight: bold; color: #1A237E;");
    aiBadgeRow->addWidget(aiBadge);
    aiBadgeRow->addWidget(aiTitle);
    aiBadgeRow->addStretch();
    statsLeftLayout->addLayout(aiBadgeRow);

    aiStatsModelLabel = new QLabel("Embedded AI: ONNX Anomaly Model v2  \xe2\x9c\x93 Active");
    aiStatsModelLabel->setStyleSheet("font-size: 11px; color: #388E3C; font-style: italic;");
    statsLeftLayout->addWidget(aiStatsModelLabel);

    aiStatsLlmLabel = new QLabel("LLM Explanation: Ollama / Llama3  \xe2\x80\xa2  Checking...");
    aiStatsLlmLabel->setStyleSheet("font-size: 11px; color: #888; font-style: italic;");
    statsLeftLayout->addWidget(aiStatsLlmLabel);

    aiStatsTotalLabel = new QLabel("0");
    aiStatsTotalLabel->setStyleSheet(
        "font-size: 54px; font-weight: bold; color: #1A237E;"
        " margin-top: -4px; margin-bottom: -4px;"
    );
    statsLeftLayout->addWidget(aiStatsTotalLabel);

    auto* totalCaption = new QLabel("files analyzed by AI");
    totalCaption->setStyleSheet("font-size: 12px; color: #666;");
    statsLeftLayout->addWidget(totalCaption);
    statsLeftLayout->addStretch(1);

    // ── Centre: classification breakdown ──
    auto* classLayout = new QVBoxLayout();
    classLayout->setSpacing(6);

    auto* classTitle = new QLabel("Classification Breakdown");
    classTitle->setStyleSheet("font-size: 13px; font-weight: bold; color: #333;");
    classLayout->addWidget(classTitle);

    auto makeStat = [&](const QString& label, const QString& color, QLabel*& valueLabel) {
        auto* row = new QHBoxLayout();
        auto* dot = new QLabel(QString("<span style='color:%1; font-size:16px;'>\xe2\x97\x8f</span>").arg(color));
        auto* lbl = new QLabel(label);
        lbl->setStyleSheet("font-size: 12px; color: #444;");
        valueLabel = new QLabel("0");
        valueLabel->setStyleSheet(QString("font-size: 16px; font-weight: bold; color: %1;").arg(color));
        valueLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        row->addWidget(dot);
        row->addWidget(lbl);
        row->addStretch();
        row->addWidget(valueLabel);
        classLayout->addLayout(row);
    };

    makeStat("Critical",     "#C62828", aiStatsCritLabel);
    makeStat("Suspicious",   "#E65100", aiStatsSuspLabel);
    makeStat("Needs Review", "#F57F17", aiStatsReviewLabel);
    makeStat("Clean",        "#2E7D32", aiStatsCleanLabel);

    classLayout->addStretch(1);

    // ── Right: average score gauge ──
    auto* scoreLayout = new QVBoxLayout();
    scoreLayout->setSpacing(6);

    auto* scoreTitle = new QLabel("Avg Anomaly Score");
    scoreTitle->setStyleSheet("font-size: 13px; font-weight: bold; color: #333;");
    scoreTitle->setAlignment(Qt::AlignCenter);
    scoreLayout->addWidget(scoreTitle);

    aiStatsAvgScoreLabel = new QLabel("—");
    aiStatsAvgScoreLabel->setStyleSheet(
        "font-size: 32px; font-weight: bold; color: #2E7D32;"
    );
    aiStatsAvgScoreLabel->setAlignment(Qt::AlignCenter);
    scoreLayout->addWidget(aiStatsAvgScoreLabel);

    // Score bar background
    auto* scoreBarBg = new QFrame();
    scoreBarBg->setFixedSize(140, 10);
    scoreBarBg->setStyleSheet(
        "QFrame { background-color: #D0D0D0; border-radius: 5px; }"
    );
    // Score bar fill (overlaid)
    aiScoreFillBar = new QFrame(scoreBarBg);
    aiScoreFillBar->setGeometry(0, 0, 0, 10);
    aiScoreFillBar->setStyleSheet(
        "QFrame { background-color: #2E7D32; border-radius: 5px; }"
    );
    auto* barCenter = new QHBoxLayout();
    barCenter->addStretch();
    barCenter->addWidget(scoreBarBg);
    barCenter->addStretch();
    scoreLayout->addLayout(barCenter);

    auto* scoreCaption = new QLabel("0.0 = safe  •  1.0 = threat");
    scoreCaption->setStyleSheet("font-size: 10px; color: #888;");
    scoreCaption->setAlignment(Qt::AlignCenter);
    scoreLayout->addWidget(scoreCaption);
    scoreLayout->addStretch(1);

    statsLayout->addLayout(statsLeftLayout, 3);
    statsLayout->addLayout(classLayout, 3);
    statsLayout->addLayout(scoreLayout, 2);
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
    severityFilter->addItems({"All Severities", "Critical", "Suspicious", "Needs Review", "High", "Medium", "Low"});
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

    threatTable = new QTableWidget(0, 7);
    threatTable->setHorizontalHeaderLabels({
        "Severity", "Name", "AI Classification", "Confidence",
        "Vendor", "Published", "Status"
    });
    threatTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    // Give the narrow columns less stretch
    threatTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    threatTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
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
        "QTableWidget::item:selected { background-color: #E8EAF6; color: #1A237E; }"
    );
    tableLayout->addWidget(threatTable);
    leftLayout->addWidget(tableFrame, 1);

    connect(threatTable, &QTableWidget::cellDoubleClicked,
            this,        &MainWindow::onThreatDoubleClicked);

    // =========================================================================
    // RIGHT-SIDE PANELS  (all in same contentLayout slot, mutually exclusive)
    // =========================================================================

    // ---- A. Threat-details panel (scrollable) ----
    detailsPanel = new QFrame();
    detailsPanel->setStyleSheet("QFrame { background-color: #F1F0EE; border-radius: 15px; color: #000000; }");
    auto* detailsOuterLayout = new QVBoxLayout(detailsPanel);
    detailsOuterLayout->setContentsMargins(0, 0, 0, 0);
    detailsOuterLayout->setSpacing(0);

    // Fixed header row (title + close button) – stays pinned at top
    auto* detailsHeaderFrame = new QFrame();
    detailsHeaderFrame->setStyleSheet("QFrame { background: transparent; }");
    auto* detailsHeaderLayout = new QHBoxLayout(detailsHeaderFrame);
    detailsHeaderLayout->setContentsMargins(25, 20, 25, 10);
    detailsTitleLabel = new QLabel("Threat Details");
    detailsTitleLabel->setStyleSheet("font-size: 22px; font-weight: bold; color: #000000;");

    auto* closeDetailsButton = new QPushButton("\xe2\x9c\x95");
    closeDetailsButton->setFixedSize(30, 30);
    closeDetailsButton->setCursor(Qt::PointingHandCursor);
    closeDetailsButton->setStyleSheet(
        "QPushButton { background-color: #E0E0E0; border-radius: 15px; font-weight: bold; border: none; }"
        "QPushButton:hover { background-color: #FF6B6B; color: white; }"
    );
    detailsHeaderLayout->addWidget(detailsTitleLabel);
    detailsHeaderLayout->addStretch();
    detailsHeaderLayout->addWidget(closeDetailsButton);
    detailsOuterLayout->addWidget(detailsHeaderFrame);

    // Scrollable content area – long findings scroll instead of clipping
    auto* detailsScroll = new QScrollArea();
    detailsScroll->setWidgetResizable(true);
    detailsScroll->setFrameShape(QFrame::NoFrame);
    detailsScroll->setStyleSheet(
        "QScrollArea { background: transparent; }"
        "QScrollBar:vertical { width: 6px; background: transparent; }"
        "QScrollBar::handle:vertical { background: #BBB; border-radius: 3px; min-height: 30px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }"
    );
    auto* detailsScrollContent = new QWidget();
    auto* detailsLayout = new QVBoxLayout(detailsScrollContent);
    detailsLayout->setContentsMargins(25, 5, 25, 25);
    detailsLayout->setSpacing(12);

    detailsDescLabel = new QLabel();
    detailsDescLabel->setWordWrap(true);
    detailsDescLabel->setStyleSheet("font-size: 14px; color: #333;");
    detailsDescLabel->setTextFormat(Qt::RichText);
    detailsLayout->addWidget(detailsDescLabel);

    detailsAILabel = new QLabel();
    detailsAILabel->setWordWrap(true);
    detailsAILabel->setStyleSheet("font-size: 14px; color: #333;");
    detailsAILabel->setTextFormat(Qt::RichText);
    detailsLayout->addWidget(detailsAILabel);

    detailsMitreLabel = new QLabel();
    detailsMitreLabel->setWordWrap(true);
    detailsMitreLabel->setStyleSheet("font-size: 14px; color: #333; margin-top: 10px;");
    detailsMitreLabel->setTextFormat(Qt::RichText);
    detailsLayout->addWidget(detailsMitreLabel);
    detailsLayout->addStretch(1);

    detailsScroll->setWidget(detailsScrollContent);
    detailsOuterLayout->addWidget(detailsScroll, 1);

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
    // 7 columns: Severity, Name, AI Classification, Confidence, Vendor, Published, Status
    QStringList cols = {severity, name, "—", "—", vendor, date, status};
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
    } else if (!sf.classificationLevel.isEmpty()) {
        // AI Anomaly Detection – use Phase 2 classification level
        cveConfirmed = false;
        QString cls = sf.classificationLevel.toUpper();
        if (cls == "CRITICAL") {
            sevText = "Critical"; sevColor = QColor("#C62828");
        } else if (cls == "SUSPICIOUS") {
            sevText = "Suspicious"; sevColor = QColor("#E65100");
        } else if (cls == "ANOMALOUS") {
            sevText = "Needs Review"; sevColor = QColor("#F57F17");
        } else {
            sevText = "Low";      sevColor = QColor("#2E7D32");
        }
        // Append score if available
        if (sf.anomalyScore > 0.0f) {
            sevText += QString(" (%1)").arg(double(sf.anomalyScore), 0, 'f', 3);
        }
    } else if (!sf.severityLevel.isEmpty()) {
        // Legacy fallback: use severity level if classification not available
        cveConfirmed = false;
        QString sev = sf.severityLevel.toUpper();
        if (sev == "CRITICAL") {
            sevText = "Critical"; sevColor = QColor("#C62828");
        } else if (sev == "HIGH") {
            sevText = "High";     sevColor = QColor("#E65100");
        } else if (sev == "MEDIUM") {
            sevText = "Medium";   sevColor = QColor("#F57F17");
        } else {
            sevText = "Low";      sevColor = QColor("#2E7D32");
        }
        if (sf.anomalyScore > 0.0f) {
            sevText += QString(" (%1)").arg(double(sf.anomalyScore), 0, 'f', 3);
        }
    } else {
        // No CVE, no AI – derive severity from detection category
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

    // ── AI Classification column ──
    QString aiClassText = "—";
    QColor  aiClassColor = Qt::black;
    if (!sf.classificationLevel.isEmpty()) {
        QString cls = sf.classificationLevel.toUpper();
        if (cls == "CRITICAL")       { aiClassText = "CRITICAL";     aiClassColor = QColor("#C62828"); }
        else if (cls == "SUSPICIOUS"){ aiClassText = "Suspicious";   aiClassColor = QColor("#E65100"); }
        else if (cls == "ANOMALOUS") { aiClassText = "Anomalous";    aiClassColor = QColor("#F57F17"); }
        else if (cls == "CLEAN")     { aiClassText = "Clean";        aiClassColor = QColor("#2E7D32"); }
        else                          { aiClassText = sf.classificationLevel; }
    }

    // ── Confidence (anomaly score) column ──
    QString confText = "—";
    QColor  confColor = Qt::black;
    if (sf.anomalyScore > 0.0f) {
        confText = QString::number(double(sf.anomalyScore), 'f', 3);
        if (sf.anomalyScore >= 0.8f)      confColor = QColor("#C62828");
        else if (sf.anomalyScore >= 0.6f) confColor = QColor("#E65100");
        else if (sf.anomalyScore >= 0.4f) confColor = QColor("#F57F17");
        else                               confColor = QColor("#2E7D32");
    }

    // Vendor: derive from category tag
    QString vendorText = sf.cveSummary.isEmpty() ? sf.category : "NVD";

    QString dateText = sf.lastModified.toString("M/dd/yyyy");

    // 7 columns: Severity, Name, AI Classification, Confidence, Vendor, Published, Status
    QStringList cols = {sevText, nameText, aiClassText, confText, vendorText, dateText, "Detected"};
    QList<QColor> colColors = {sevColor, Qt::black, aiClassColor, confColor,
                               Qt::black, Qt::black, Qt::black};
    for (int i = 0; i < cols.size(); ++i) {
        auto* item = new QTableWidgetItem(cols[i]);
        item->setForeground(QBrush(colColors[i]));
        if (i == 0 || i == 2) item->setFont(QFont("", -1, QFont::Bold));
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
    // ── Highlight the selected row ──
    threatTable->selectRow(row);

    QString threatName = threatTable->item(row, 1)->text();
    QString vendor     = threatTable->item(row, 4)->text();   // col 4 after AI columns

    // Check if this row has scan-finding data (UserRole set)
    QString filePath   = threatTable->item(row, 0)->data(Qt::UserRole).toString();
    QString reason     = threatTable->item(row, 0)->data(Qt::UserRole + 1).toString();
    QString cveId      = threatTable->item(row, 0)->data(Qt::UserRole + 2).toString();
    QString cveSummary = threatTable->item(row, 0)->data(Qt::UserRole + 3).toString();

    detailsTitleLabel->setText(threatName);

    if (!filePath.isEmpty()) {
        // Scan-derived entry – check if it has AI metadata
        int findingIdx = -1;
        for (int i = 0; i < m_findings.size(); ++i) {
            if (m_findings[i].filePath == filePath) {
                findingIdx = i;
                break;
            }
        }

        if (findingIdx >= 0 && (!m_findings[findingIdx].classificationLevel.isEmpty() ||
                                  !m_findings[findingIdx].severityLevel.isEmpty())) {
            // ════════════════════════════════════════════════════════════
            //  AI Anomaly Detection finding – rich detail panel
            // ════════════════════════════════════════════════════════════
            m_detailFindingIdx = findingIdx;   // track which finding is shown
            const SuspiciousFile& sf = m_findings[findingIdx];

            // Resolve display level + colour
            QString displayLevel = !sf.classificationLevel.isEmpty()
                                       ? sf.classificationLevel
                                       : sf.severityLevel;
            QString levelColor, levelBg;
            QString levelUpper = displayLevel.toUpper();
            if (levelUpper == "CRITICAL")       { levelColor = "#C62828"; levelBg = "#FDECEA"; }
            else if (levelUpper == "SUSPICIOUS") { levelColor = "#E65100"; levelBg = "#FFF3E0"; }
            else if (levelUpper == "HIGH")       { levelColor = "#E65100"; levelBg = "#FFF3E0"; }
            else if (levelUpper == "ANOMALOUS")  { levelColor = "#F57F17"; levelBg = "#FFFDE7"; }
            else if (levelUpper == "MEDIUM")     { levelColor = "#F57F17"; levelBg = "#FFFDE7"; }
            else                                 { levelColor = "#2E7D32"; levelBg = "#E8F5E9"; }

            // ── File info + score hero section ──
            // Truncate very long paths to keep the layout clean
            QString displayPath = filePath;
            if (displayPath.length() > 120)
                displayPath = "\xe2\x80\xa6" + displayPath.right(115);

            int barPct = qBound(0, int(sf.anomalyScore * 100), 100);
            QString barColor = (barPct >= 80) ? "#C62828" : (barPct >= 60) ? "#E65100"
                             : (barPct >= 40) ? "#F57F17" : "#2E7D32";

            QString descHtml;
            // Score hero – large badge + progress bar at the top for instant readability
            descHtml += "<div style='background-color:#FAFAFA; border-radius:10px; padding:14px;"
                        " margin:0 0 8px 0; border:1px solid #E0E0E0;'>";
            descHtml += QString("<div style='display:flex; align-items:center;'>"
                        "<span style='background-color:%1; color:%2; padding:4px 12px;"
                        " border-radius:6px; font-weight:bold; font-size:14px;'>%3</span>"
                        "&nbsp;&nbsp;"
                        "<span style='font-size:24px; font-weight:bold; color:%4;'>%5</span>"
                        "<span style='font-size:14px; color:#888;'> / 1.000</span>"
                        "</div>")
                          .arg(levelBg, levelColor, displayLevel,
                               barColor, QString::number(double(sf.anomalyScore), 'f', 3));
            // Score bar
            descHtml += QString("<div style='background-color:#E0E0E0; border-radius:5px;"
                        " height:10px; width:100%%; margin:8px 0 6px 0;'>"
                        "<div style='background-color:%1; border-radius:5px;"
                        " height:10px; width:%2%%;'></div></div>")
                          .arg(barColor).arg(barPct);
            descHtml += QString("<span style='font-size:11px; color:#888;'>"
                        "Severity: <b>%1</b> &nbsp;|&nbsp; Threshold: %2</span>")
                          .arg(!sf.severityLevel.isEmpty() ? sf.severityLevel : "N/A")
                          .arg(double(sf.anomalyThreshold), 0, 'f', 3);
            descHtml += "</div>";

            // File metadata
            descHtml += "<span style='font-size:11px; color:#777; word-wrap:break-word;'>"
                        + displayPath + "</span><br>";
            descHtml += "<span style='font-size:12px; color:#555;'>"
                        + QString::number(sf.sizeBytes) + " bytes &nbsp;|&nbsp; "
                        + sf.lastModified.toString("yyyy-MM-dd hh:mm:ss") + "</span>";
            detailsDescLabel->setText(descHtml);

            // ════════════════════════════════════════════════════════════
            //  "Why flagged?" – concise top-3 summary for demo clarity
            // ════════════════════════════════════════════════════════════
            QString aiHtml;
            if (!sf.keyIndicators.isEmpty()) {
                aiHtml += "<div style='background-color:#FFF3E0; border-radius:8px; padding:10px 14px;"
                          " margin:0 0 8px 0; border-left:4px solid #FF9800;'>";
                aiHtml += "<span style='font-size:13px; font-weight:bold; color:#E65100;'>"
                          "\xe2\x9a\xa0 Why was this flagged?</span><br>";
                int count = 0;
                for (const QString& ind : sf.keyIndicators) {
                    if (count >= 3) break;
                    aiHtml += "<span style='font-size:12px; color:#444;'>\xe2\x80\xa2 "
                              + ind + "</span><br>";
                    ++count;
                }
                aiHtml += "</div>";
            }

            // ════════════════════════════════════════════════════════════
            //  Embedded AI Analysis section (ONNX model output)
            // ════════════════════════════════════════════════════════════
            aiHtml += "<div style='background-color:#EDE7F6; border-radius:10px; padding:14px;"
                      " margin:0 0 4px 0; border-left:4px solid #5C6BC0;'>";
            aiHtml += "<span style='font-size:14px; font-weight:bold; color:#1A237E;'>"
                      "\xF0\x9F\xA7\xA0 Embedded AI Analysis</span>"
                      "<span style='font-size:10px; color:#888; margin-left:6px;'>"
                      "ONNX Anomaly Model</span><br><br>";

            // Embedded AI Summary
            if (!sf.aiSummary.isEmpty()) {
                aiHtml += "<span style='font-size:12px; color:#333; line-height:1.5;'>"
                          + sf.aiSummary + "</span><br>";
            } else {
                aiHtml += "<span style='font-size:12px; color:#999; font-style:italic;'>"
                          "No embedded AI summary available for this file.</span><br>";
            }

            // Full indicator list (if more than the top-3 shown above)
            if (sf.keyIndicators.size() > 3) {
                aiHtml += "<br><span style='font-size:11px; font-weight:bold; color:#555;'>"
                          "All indicators:</span><br>";
                for (const QString& ind : sf.keyIndicators) {
                    aiHtml += "<span style='font-size:11px; color:#555;'>\xe2\x96\xb8 "
                              + ind + "</span><br>";
                }
            }

            aiHtml += "<br><span style='font-size:10px; color:#388E3C; font-weight:bold;'>"
                      "\xe2\x9c\x93 Embedded AI: Active</span>";
            aiHtml += "</div>";

            // ════════════════════════════════════════════════════════════
            //  LLM Explanation (Ollama / Llama3) — visually subordinate
            //  Trigger on-demand request BEFORE rendering so m_llmPendingIndex
            //  is set and the loading state shows on the first paint.
            // ════════════════════════════════════════════════════════════
            if (sf.aiExplanation.isEmpty())
                requestLlmExplanation(findingIdx);

            aiHtml += "<div style='background-color:#F5F9FF; border-radius:8px; padding:12px;"
                      " margin:4px 0; border-left:3px solid #90CAF9;'>";
            aiHtml += "<span style='font-size:13px; font-weight:bold; color:#0D47A1;'>"
                      "\xF0\x9F\x92\xAC LLM Explanation</span>"
                      "<span style='font-size:10px; color:#888; margin-left:6px;'>"
                      "Ollama / Llama3</span><br>";

            if (!sf.aiExplanation.isEmpty()) {
                // Show LLM text in a readable block with good line height
                aiHtml += "<br><span style='font-size:12px; color:#333; line-height:1.5;'>"
                          + sf.aiExplanation + "</span><br>";
                aiHtml += "<br><span style='font-size:10px; color:#1565C0; font-weight:bold;'>"
                          "\xe2\x9c\x93 LLM: Active</span>";
            } else if (m_llmPendingIndex == findingIdx) {
                // LLM request is in flight for this finding — show loading state
                aiHtml += "<br><span style='font-size:12px; color:#1565C0; font-style:italic;'>"
                          "\xe2\x8f\xb3 Generating LLM explanation...</span><br>";
                aiHtml += "<br><span style='font-size:10px; color:#90CAF9;'>"
                          "LLM: Processing</span>";
            } else {
                // No explanation yet and not currently loading
                aiHtml += "<br><span style='font-size:12px; color:#999; font-style:italic;'>"
                          "The LLM explanation service is not currently running. "
                          "The embedded AI analysis above provides the full assessment.</span><br>";
                aiHtml += "<br><span style='font-size:10px; color:#B0B0B0;'>"
                          "\xe2\x9c\x97 LLM: Unavailable</span>";
            }

            aiHtml += "</div>";
            detailsAILabel->setText(aiHtml);

            // ── Recommended Actions + metadata ──
            QString actHtml;
            if (!sf.recommendedActions.isEmpty()) {
                actHtml += "<div style='background-color:#FFF8E1; border-radius:8px; padding:10px;"
                           " margin:4px 0; border-left:4px solid #F57F17;'>";
                actHtml += "<b style='font-size:13px;'>Recommended Actions</b>"
                           "<span style='font-size:10px; color:#888;'> (Embedded AI)</span><br>";
                for (int i = 0; i < sf.recommendedActions.size(); ++i) {
                    actHtml += QString("<span style='font-size:12px; color:#444;'>%1. %2</span><br>")
                                   .arg(i + 1).arg(sf.recommendedActions[i]);
                }
                actHtml += "</div><br>";
            }

            // CVE info if available
            if (!cveId.isEmpty()) {
                actHtml += "<b>CVE:</b> " + cveId;
                if (!cveSummary.isEmpty())
                    actHtml += "<br><b>NVD:</b> " + cveSummary;
                actHtml += "<br><br>";
            }

            actHtml += "<span style='font-size:12px;'>"
                       "<b>Detection Engine:</b> " + vendor + "<br>"
                       "<b>Source:</b> <span style='background-color:#E8EAF6; padding:3px 8px;"
                       " border-radius:4px; color:#1A237E; font-weight:bold;'>"
                       "\xF0\x9F\xA7\xA0 Odysseus AI Scanner</span></span>";
            detailsMitreLabel->setText(actHtml);
        } else {
            // Non-AI scan finding (hash-based or other)
            QString displayPath2 = filePath;
            if (displayPath2.length() > 120)
                displayPath2 = "\xe2\x80\xa6" + displayPath2.right(115);
            detailsDescLabel->setText(
                "<b>File Path:</b><br>"
                "<span style='font-size:11px; color:#777; word-wrap:break-word;'>"
                + displayPath2 + "</span><br><br>"
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
        }
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
    m_detailFindingIdx = -1;
    showPanel(ActivePanel::None);
}

void MainWindow::onSimulateThreatClicked()
{
    ThreatCard card(this);

    // Use the new structured API
    card.setFileName("suspicious_payload.exe");
    card.setSeverityLevel("High");
    card.setAnomalyScore(0.847f, 0.500f);
    card.setSummary(
        "This file exhibits characteristics consistent with a packed or "
        "encrypted executable. High entropy and stripped debug info suggest "
        "deliberate obfuscation to evade signature-based detection."
    );
    card.setKeyIndicators({
        "Very high Shannon entropy (7.42/8.0) — suggests encryption or packing",
        "PE section with very high entropy — likely packed/encrypted code",
        "No debug information — stripped binary, common in malware",
        "Anomalous PE section names — possible packer (UPX, Themida)"
    });
    card.setRecommendedActions({
        "Quarantine the file and prevent execution",
        "Submit file hash to VirusTotal for multi-engine verification",
        "Review system logs for signs of prior execution",
        "Scan connected systems for lateral movement indicators"
    });
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
    m_scanMode = ScanMode::Full;
    QString rootPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation);
    if (rootPath.isEmpty())
        rootPath = QDir::rootPath();
    startScanForPath(rootPath);
}

void MainWindow::onPartialScanRequested(const QString& path)
{
    m_scanMode = ScanMode::Partial;
    startScanForPath(path);
}

void MainWindow::onResumeScanRequested()
{
    m_scanMode = ScanMode::Resumed;

    // Load the root used in the last scan; fall back to home if nothing saved yet.
    QString rootPath;
    if (m_db)
        rootPath = m_db->loadLastScanRoot();
    if (rootPath.isEmpty()) {
        rootPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation);
        if (rootPath.isEmpty())
            rootPath = QDir::rootPath();
    }

    startScanForPath(rootPath);
}

void MainWindow::startScanForPath(const QString& rootPath)
{
    // Reset state
    m_findings.clear();
    m_elapsedSeconds    = 0;
    m_cveQueryIndex     = 0;
    m_pendingCveQueries = 0;
    m_driveTotalBytes   = 0;
    m_scanActive        = true;

    scanResultsList->clear();
    scanSummaryLabel->setText("Scanning...");
    scanStatusLabel->setText("Scanning in progress...");
    scanStatusLabel->setStyleSheet("font-size: 13px; font-weight: bold; color: #1A1AEE;");
    scanElapsedLabel->setText("Elapsed: 00:00");
    scanStorageLabel->setText("Storage: —");
    scanPathLabel->clear();
    scanProgressBar->setValue(0);

    // Reset AI dashboard for new scan
    aiStatsTotalLabel->setText("0");
    aiStatsCritLabel->setText("0");
    aiStatsSuspLabel->setText("0");
    aiStatsReviewLabel->setText("0");
    aiStatsCleanLabel->setText("0");
    aiStatsAvgScoreLabel->setText("—");
    aiStatsAvgScoreLabel->setStyleSheet("font-size: 32px; font-weight: bold; color: #2E7D32;");
    aiScoreFillBar->setFixedWidth(0);
    aiStatsModelLabel->setText("Embedded AI: ONNX Anomaly Model v2  \xe2\x9c\x93 Scanning...");
    aiStatsModelLabel->setStyleSheet("font-size: 11px; color: #388E3C; font-style: italic;");
    aiStatsLlmLabel->setText("LLM Explanation: Ollama / Llama3  \xe2\x80\xa2  Waiting for findings...");

    showPanel(ActivePanel::ScanResults);

    runScanButton->setText("Cancel Scan");
    runScanButton->setStyleSheet(
        "QPushButton { background-color: #CC2200; color: white; border-radius: 15px;"
        " padding: 8px 25px; font-weight: bold; font-size: 14px; }"
        "QPushButton:hover { background-color: #AA1100; }"
    );

    qDebug() << "=== Odysseus File Scan Started ===" << rootPath
             << "(mode:" << static_cast<int>(m_scanMode) << ")";
    m_scanTimer->start();

    // ---- Storage denominator depends on scan mode ----
    if (m_scanMode == ScanMode::Full || m_scanMode == ScanMode::Resumed) {
        // Full / resumed scan: show total drive capacity immediately.
        QStorageInfo si(rootPath);
        m_driveTotalBytes = si.bytesTotal();
        if (m_driveTotalBytes > 0)
            scanStorageLabel->setText("Storage: 0 B / " + formatBytes(m_driveTotalBytes));
    } else {
        // Partial scan: calculate the actual directory size in a background thread
        // so we don't block the UI while walking potentially large directory trees.
        scanStorageLabel->setText("Storage: Calculating...");
        QString capturedPath = rootPath;
        auto* sizeThread = QThread::create([this, capturedPath]() {
            qint64 total = 0;
            QDirIterator it(capturedPath,
                            QDir::Files | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot,
                            QDirIterator::Subdirectories);
            while (it.hasNext()) {
                if (QThread::currentThread()->isInterruptionRequested())
                    return;
                it.next();
                total += it.fileInfo().size();
            }
            QMetaObject::invokeMethod(this, [this, total]() {
                m_driveTotalBytes = total;
                // Only update label if the scan is still in progress;
                // onScanFinished may have already written the final summary.
                if (m_scanActive && total > 0)
                    scanStorageLabel->setText("Storage: 0 B / " + formatBytes(total));
            }, Qt::QueuedConnection);
        });
        connect(sizeThread, &QThread::finished, sizeThread, &QObject::deleteLater);
        sizeThread->start();
    }

    // Persist this scan's root so "Scan from Last Point" can resume here next time.
    if (m_db)
        m_db->saveLastScanRoot(rootPath);

    // Load scan cache and pass it to the worker for incremental scanning.
    QHash<QString, CacheEntry> cache;
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

    // Use classification-aware log label instead of always "[SUSPICIOUS]"
    QString logLabel = "[FLAGGED]";
    if (!file.classificationLevel.isEmpty()) {
        QString cls = file.classificationLevel.toUpper();
        if (cls == "CRITICAL")       logLabel = "[CRITICAL]";
        else if (cls == "SUSPICIOUS") logLabel = "[SUSPICIOUS]";
        else if (cls == "ANOMALOUS") logLabel = "[NEEDS REVIEW]";
    }
    qDebug().noquote() << logLabel << file.category
             << "|" << file.filePath;

    // Colour-code in scan panel list – use AI severity if available
    QString prefix = "[!]";
    QColor  bg     = QColor("#FFF8E1");

    if (!file.classificationLevel.isEmpty()) {
        // AI Anomaly Detection – use Phase 2 classification level
        QString cls = file.classificationLevel.toUpper();
        if (cls == "CRITICAL")       { prefix = "[CRIT]"; bg = QColor("#FDECEA"); }
        else if (cls == "SUSPICIOUS"){ prefix = "[SUSP]"; bg = QColor("#FFF3E0"); }
        else if (cls == "ANOMALOUS") { prefix = "[REV]";  bg = QColor("#FFFDE7"); }
        else                         { prefix = "[LOW]";  bg = QColor("#F1F8E9"); }
    } else if (!file.severityLevel.isEmpty()) {
        // Legacy severity fallback
        QString sev = file.severityLevel.toUpper();
        if (sev == "CRITICAL")     { prefix = "[CRIT]"; bg = QColor("#FDECEA"); }
        else if (sev == "HIGH")    { prefix = "[HIGH]"; bg = QColor("#FFF3E0"); }
        else if (sev == "MEDIUM")  { prefix = "[MED]";  bg = QColor("#FFFDE7"); }
        else if (sev == "LOW")     { prefix = "[LOW]";  bg = QColor("#F1F8E9"); }
    } else {
        // Legacy / hash-based detection – derive from category
        if (file.category.contains("Known Malware") || file.category.contains("PE Binary") ||
            file.category.contains("ELF Binary")    || file.category.contains("Mach-O")) {
            prefix = "[CRIT]"; bg = QColor("#FDECEA");
        } else if (file.category.contains("High-Risk") || file.category.contains("Persistence") ||
                   file.category.contains("Temp")) {
            prefix = "[HIGH]"; bg = QColor("#FFF3E0");
        } else if (file.category.contains("Suspicious Name") || file.category.contains("Double-Extension")) {
            prefix = "[MED]";  bg = QColor("#FFFDE7");
        }
    }

    // Build display text with score if available
    QString scoreInfo;
    if (file.anomalyScore > 0.0f) {
        scoreInfo = QString(" [Score: %1]").arg(file.anomalyScore, 0, 'f', 3);
    }

    QString displayText = QString("%1 %2%3\n   %4\n   %5")
        .arg(prefix)
        .arg(file.fileName)
        .arg(scoreInfo)
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

    // Live tally by classification level
    int nCrit = 0, nSusp = 0, nReview = 0;
    for (const SuspiciousFile& f : m_findings) {
        QString cls = f.classificationLevel.toUpper();
        if (cls == "CRITICAL")       ++nCrit;
        else if (cls == "SUSPICIOUS") ++nSusp;
        else                          ++nReview;
    }
    QString tally;
    if (nCrit > 0)
        tally += QString("%1 critical").arg(nCrit);
    if (nSusp > 0) {
        if (!tally.isEmpty()) tally += ", ";
        tally += QString("%1 suspicious").arg(nSusp);
    }
    if (nReview > 0) {
        if (!tally.isEmpty()) tally += ", ";
        tally += QString("%1 needs review").arg(nReview);
    }
    if (tally.isEmpty()) tally = "0";
    scanSummaryLabel->setText(
        QString("Findings so far: %1").arg(tally)
    );

    // ── Update AI dashboard stats live ──
    aiStatsTotalLabel->setText(QString::number(m_findings.size()));
    aiStatsCritLabel->setText(QString::number(nCrit));
    aiStatsSuspLabel->setText(QString::number(nSusp));
    aiStatsReviewLabel->setText(QString::number(nReview));

    // Compute average anomaly score across all flagged files
    float scoreSum = 0.0f;
    int   scoreN   = 0;
    for (const SuspiciousFile& f : m_findings) {
        if (f.anomalyScore > 0.0f) {
            scoreSum += f.anomalyScore;
            ++scoreN;
        }
    }
    if (scoreN > 0) {
        float avg = scoreSum / float(scoreN);
        aiStatsAvgScoreLabel->setText(QString::number(double(avg), 'f', 3));
        // Color-code average
        QString avgColor = (avg >= 0.8f) ? "#C62828" : (avg >= 0.6f) ? "#E65100"
                         : (avg >= 0.4f) ? "#F57F17" : "#2E7D32";
        aiStatsAvgScoreLabel->setStyleSheet(
            QString("font-size: 32px; font-weight: bold; color: %1;").arg(avgColor));
        // Update score fill bar
        int fillW = qBound(0, int(avg * 140), 140);
        aiScoreFillBar->setFixedWidth(fillW);
        aiScoreFillBar->setStyleSheet(
            QString("QFrame { background-color: %1; border-radius: 5px; }").arg(avgColor));
    }

    aiStatsModelLabel->setText(
        QString("Embedded AI: ONNX Anomaly Model v2  \xe2\x9c\x93 Analyzing (%1 flagged)")
            .arg(m_findings.size())
    );
    aiStatsModelLabel->setStyleSheet("font-size: 11px; color: #388E3C; font-style: italic;");

    // Update LLM status based on whether any finding got an LLM explanation
    bool anyLlm = false;
    for (const SuspiciousFile& f2 : m_findings) {
        if (!f2.aiExplanation.isEmpty()) { anyLlm = true; break; }
    }
    if (anyLlm) {
        aiStatsLlmLabel->setText("LLM Explanation: Ollama / Llama3  \xe2\x9c\x93 Active");
        aiStatsLlmLabel->setStyleSheet("font-size: 11px; color: #1565C0; font-style: italic;");
    } else if (file.llmAvailable) {
        aiStatsLlmLabel->setText("LLM Explanation: Ollama / Llama3  \xe2\x80\xa2  Connected (no output yet)");
        aiStatsLlmLabel->setStyleSheet("font-size: 11px; color: #888; font-style: italic;");
    } else {
        aiStatsLlmLabel->setText("LLM Explanation: Ollama / Llama3  \xe2\x9c\x97 Unavailable");
        aiStatsLlmLabel->setStyleSheet("font-size: 11px; color: #E65100; font-style: italic;");
    }
}

void MainWindow::onScanFinished(int totalScanned, int suspiciousCount, int elapsedSeconds, qint64 bytesScanned)
{
    Q_UNUSED(suspiciousCount)   // per-category counts are computed from m_findings instead
    m_scanTimer->stop();
    m_scanActive = false;

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

    // ── Compute per-category counts from findings ──────────────────────
    int nCrit = 0, nSusp = 0, nReview = 0;
    for (const SuspiciousFile& sf : m_findings) {
        QString cls = sf.classificationLevel.toUpper();
        if (cls == "CRITICAL")        ++nCrit;
        else if (cls == "SUSPICIOUS") ++nSusp;
        else                          ++nReview;   // Anomalous or unset
    }
    int nActionable = nCrit + nSusp;   // truly suspicious or critical

    if (m_findings.isEmpty()) {
        qDebug() << "Nothing to do";
        scanStatusLabel->setText("\xE2\x9C\x85 Scan complete — your system looks clean.");
        scanStatusLabel->setStyleSheet("font-size: 14px; font-weight: bold; color: #2E7D32;");

        auto* item = new QListWidgetItem(
            "\xF0\x9F\x9B\xA1 No suspicious files detected. All scanned files passed AI analysis.",
            scanResultsList
        );
        item->setForeground(QBrush(QColor("#2E7D32")));

        scanSummaryLabel->setText(
            QString("Scanned %1 file(s) with embedded AI — all clear.").arg(totalScanned)
        );
    } else {
        qDebug() << "=== Scan Complete ===";
        qDebug() << "Total files scanned:" << totalScanned;
        qDebug() << "Critical:" << nCrit << " Suspicious:" << nSusp << " Needs Review:" << nReview;
        for (const SuspiciousFile& sf : m_findings)
            qDebug() << " " << sf.filePath << "->" << sf.category << sf.classificationLevel;

        // Build a bucketed status line
        QStringList parts;
        if (nCrit > 0)   parts << QString("%1 critical").arg(nCrit);
        if (nSusp > 0)   parts << QString("%1 suspicious").arg(nSusp);
        if (nReview > 0)  parts << QString("%1 needs review").arg(nReview);

        QString statusText;
        if (nActionable > 0) {
            statusText = QString("Scan complete — %1.").arg(parts.join(", "));
            scanStatusLabel->setStyleSheet("font-size: 13px; font-weight: bold; color: #B71C1C;");
        } else {
            // Only "needs review" items — no true threats
            statusText = QString("Scan complete — %1 file(s) flagged for review (no confirmed threats).")
                             .arg(nReview);
            scanStatusLabel->setStyleSheet("font-size: 13px; font-weight: bold; color: #F57F17;");
        }
        scanStatusLabel->setText(statusText);

        // Only run CVE queries for Suspicious/Critical findings
        int cveCount = 0;
        for (int i = 0; i < m_findings.size(); ++i) {
            QString cls = m_findings[i].classificationLevel.toUpper();
            if (cls == "CRITICAL" || cls == "SUSPICIOUS") {
                lookupCveForFinding(i);
                ++cveCount;
            }
        }
        if (cveCount > 0) {
            scanSummaryLabel->setText(
                QString("Looking up CVEs for %1 finding(s)...").arg(cveCount)
            );
        } else {
            scanSummaryLabel->setText(
                QString("%1 file(s) flagged for review — no CVE lookup needed.").arg(nReview)
            );
        }
    }

    // ── Final AI dashboard update ──
    aiStatsTotalLabel->setText(QString::number(totalScanned));
    aiStatsCritLabel->setText(QString::number(nCrit));
    aiStatsSuspLabel->setText(QString::number(nSusp));
    aiStatsReviewLabel->setText(QString::number(nReview));
    aiStatsCleanLabel->setText(QString::number(totalScanned - m_findings.size()));

    // Final average anomaly score
    {
        float scoreSum = 0.0f;
        int   scoreN   = 0;
        for (const SuspiciousFile& sf2 : m_findings) {
            if (sf2.anomalyScore > 0.0f) {
                scoreSum += sf2.anomalyScore;
                ++scoreN;
            }
        }
        if (scoreN > 0) {
            float avg = scoreSum / float(scoreN);
            aiStatsAvgScoreLabel->setText(QString::number(double(avg), 'f', 3));
            QString avgColor = (avg >= 0.8f) ? "#C62828" : (avg >= 0.6f) ? "#E65100"
                             : (avg >= 0.4f) ? "#F57F17" : "#2E7D32";
            aiStatsAvgScoreLabel->setStyleSheet(
                QString("font-size: 32px; font-weight: bold; color: %1;").arg(avgColor));
            int fillW = qBound(0, int(avg * 140), 140);
            aiScoreFillBar->setFixedWidth(fillW);
            aiScoreFillBar->setStyleSheet(
                QString("QFrame { background-color: %1; border-radius: 5px; }").arg(avgColor));
        } else {
            aiStatsAvgScoreLabel->setText("0.000");
            aiStatsAvgScoreLabel->setStyleSheet("font-size: 32px; font-weight: bold; color: #2E7D32;");
            aiScoreFillBar->setFixedWidth(0);
        }
    }

    aiStatsModelLabel->setText(
        QString("Embedded AI: ONNX Anomaly Model v2  \xe2\x9c\x93 Scan complete (%1s)")
            .arg(elapsedSeconds)
    );
    aiStatsModelLabel->setStyleSheet("font-size: 11px; color: #388E3C; font-style: italic;");

    // Final LLM status
    {
        bool anyLlm = false;
        for (const SuspiciousFile& sf3 : m_findings) {
            if (!sf3.aiExplanation.isEmpty()) { anyLlm = true; break; }
        }
        if (anyLlm) {
            aiStatsLlmLabel->setText("LLM Explanation: Ollama / Llama3  \xe2\x9c\x93 Active");
            aiStatsLlmLabel->setStyleSheet("font-size: 11px; color: #1565C0; font-style: italic;");
        } else {
            aiStatsLlmLabel->setText("LLM Explanation: Ollama / Llama3  \xe2\x9c\x97 Unavailable");
            aiStatsLlmLabel->setStyleSheet("font-size: 11px; color: #E65100; font-style: italic;");
        }
    }

    // Save to history regardless
    ScanRecord record;
    record.timestamp       = QDateTime::currentDateTime();
    record.totalScanned    = totalScanned;
    record.suspiciousCount = m_findings.size();   // total flagged (all non-Clean)
    record.criticalCount   = nCrit;
    record.suspiciousOnly  = nSusp;
    record.reviewCount     = nReview;
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
    m_scanActive = false;

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
            // Recompute per-category counts from findings if available
            int crit = r.criticalCount, susp = r.suspiciousOnly, rev = r.reviewCount;
            if (crit == 0 && susp == 0 && rev == 0 && !r.findings.isEmpty()) {
                for (const SuspiciousFile& sf : r.findings) {
                    QString cls = sf.classificationLevel.toUpper();
                    if (cls == "CRITICAL")        ++crit;
                    else if (cls == "SUSPICIOUS") ++susp;
                    else                          ++rev;
                }
            }

            // Build bucketed summary for history entry
            QStringList cats;
            if (crit > 0)  cats << QString("%1 crit").arg(crit);
            if (susp > 0)  cats << QString("%1 susp").arg(susp);
            if (rev > 0)   cats << QString("%1 review").arg(rev);
            // Fallback for old DB records with no per-category data
            QString buckets;
            if (cats.isEmpty() && r.suspiciousCount > 0)
                buckets = QString("%1 flagged").arg(r.suspiciousCount);
            else if (cats.isEmpty())
                buckets = "clean";
            else
                buckets = cats.join(", ");

            QString label = QString("[%1]  %2 / %3 total  (%4)")
                .arg(r.timestamp.toString("yyyy-MM-dd hh:mm:ss"))
                .arg(buckets)
                .arg(r.totalScanned)
                .arg(formatElapsed(r.elapsedSeconds));
            auto* item = new QListWidgetItem(label);

            QColor color = QColor("#2E7D32");  // green = clean
            if (crit > 0)       color = QColor("#B71C1C");  // red
            else if (susp > 0)  color = QColor("#E65100");  // orange
            else if (rev > 0)   color = QColor("#F57F17");  // amber
            else if (r.suspiciousCount > 0) color = QColor("#B71C1C");  // legacy fallback
            item->setForeground(QBrush(color));
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

    // Recompute per-category counts from findings if needed
    int dCrit = record.criticalCount, dSusp = record.suspiciousOnly, dRev = record.reviewCount;
    if (dCrit == 0 && dSusp == 0 && dRev == 0 && !record.findings.isEmpty()) {
        for (const SuspiciousFile& sf : record.findings) {
            QString cls = sf.classificationLevel.toUpper();
            if (cls == "CRITICAL")        ++dCrit;
            else if (cls == "SUSPICIOUS") ++dSusp;
            else                          ++dRev;
        }
    }
    QStringList buckets;
    if (dCrit > 0)  buckets << QString("%1 critical").arg(dCrit);
    if (dSusp > 0)  buckets << QString("%1 suspicious").arg(dSusp);
    if (dRev > 0)   buckets << QString("%1 needs review").arg(dRev);
    QString bucketStr;
    if (buckets.isEmpty() && record.suspiciousCount > 0)
        bucketStr = QString("%1 flagged").arg(record.suspiciousCount);
    else if (buckets.isEmpty())
        bucketStr = "None";
    else
        bucketStr = buckets.join(", ");

    histDetailSummaryLabel->setText(
        QString("Files scanned: %1\n"
                "Findings: %2\n"
                "Duration: %3")
            .arg(record.totalScanned)
            .arg(bucketStr)
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
// ON-DEMAND LLM EXPLANATION
// ============================================================================

void MainWindow::requestLlmExplanation(int findingIndex)
{
    if (findingIndex < 0 || findingIndex >= m_findings.size())
        return;

    // Already have an explanation cached — nothing to do.
    if (!m_findings[findingIndex].aiExplanation.isEmpty())
        return;

    // Another request is already in flight — don't pile up.
    if (m_llmPendingIndex >= 0)
        return;

    // Lazy-init: create the LLMExplainer once and probe Ollama availability.
    if (!m_llmChecked) {
        m_llmChecked = true;
        m_llmExplainer = new LLMExplainer();
        m_llmReachable = m_llmExplainer->isAvailable();
        if (m_llmReachable) {
            qDebug() << "[LLM] Ollama is reachable — on-demand explanations enabled.";
        } else {
            qDebug() << "[LLM] Ollama not reachable — on-demand explanations disabled.";
            delete m_llmExplainer;
            m_llmExplainer = nullptr;
        }
    }

    if (!m_llmReachable || !m_llmExplainer)
        return;

    m_llmPendingIndex = findingIndex;

    // Capture what we need for the background callback.
    const SuspiciousFile& sf = m_findings[findingIndex];
    QString filePath            = sf.filePath;
    QString classificationLevel = sf.classificationLevel;
    float   anomalyScore        = sf.anomalyScore;
    int     idx                 = findingIndex;

    // Extract features on the main thread (fast ~ms I/O for small files).
    std::vector<float> features = extractFeatures(filePath.toStdString());

    // Fire the async LLM request — explainAsync spawns a detached std::thread
    // internally; the callback runs on that background thread, so we use
    // QMetaObject::invokeMethod to deliver the result to the UI thread.
    m_llmExplainer->explainAsync(
        filePath.toStdString(),
        features,
        anomalyScore,
        [this, idx](const std::string& response, bool success) {
            QString explanation = success ? QString::fromStdString(response) : QString();
            QMetaObject::invokeMethod(this, [this, idx, explanation, success]() {
                onLlmExplanationReady(idx, explanation, success);
            }, Qt::QueuedConnection);
        },
        classificationLevel.toStdString()
    );
}

void MainWindow::onLlmExplanationReady(int findingIndex, const QString& explanation, bool success)
{
    m_llmPendingIndex = -1;

    if (findingIndex < 0 || findingIndex >= m_findings.size())
        return;

    if (success && !explanation.isEmpty()) {
        // Cache the explanation in the in-memory finding.
        m_findings[findingIndex].aiExplanation = explanation;
        m_findings[findingIndex].llmAvailable  = true;

        qDebug() << "[LLM] Explanation received for finding" << findingIndex
                 << "(" << m_findings[findingIndex].fileName << ")";

        // Persist to DB cache so it survives app restart.
        if (m_db) {
            CacheEntry ce;
            const SuspiciousFile& sf = m_findings[findingIndex];
            ce.filePath            = sf.filePath;
            ce.lastModified        = sf.lastModified.toString(Qt::ISODate);
            ce.fileSize            = sf.sizeBytes;
            ce.isFlagged           = true;
            ce.reason              = sf.reason;
            ce.category            = sf.category;
            ce.classificationLevel = sf.classificationLevel;
            ce.severityLevel       = sf.severityLevel;
            ce.anomalyScore        = sf.anomalyScore;
            ce.aiSummary           = sf.aiSummary;
            ce.keyIndicators       = sf.keyIndicators;
            ce.recommendedActions  = sf.recommendedActions;
            ce.aiExplanation       = sf.aiExplanation;
            ce.llmAvailable        = true;
            m_db->flushScanCache({ce});
        }
    } else {
        qDebug() << "[LLM] Explanation failed for finding" << findingIndex;
    }

    // Update the detail panel if this finding is still being viewed.
    if (m_detailFindingIdx == findingIndex) {
        refreshDetailLlmSection(m_findings[findingIndex]);
    }

    // Update dashboard LLM status.
    bool anyLlm = false;
    for (const SuspiciousFile& f : m_findings) {
        if (!f.aiExplanation.isEmpty()) { anyLlm = true; break; }
    }
    if (anyLlm) {
        aiStatsLlmLabel->setText("LLM Explanation: Ollama / Llama3  \xe2\x9c\x93 Active");
        aiStatsLlmLabel->setStyleSheet("font-size: 11px; color: #1565C0; font-style: italic;");
    }
}

void MainWindow::refreshDetailLlmSection(const SuspiciousFile& sf)
{
    // Rebuild just the LLM portion of the AI label.
    // We need to regenerate the full aiHtml since QLabel doesn't support partial updates.
    // Read current text, find the LLM div, and replace it.
    // Simpler approach: re-render the entire detailsAILabel content.

    // First, reconstruct the "Why flagged?" + Embedded AI + LLM sections.
    QString levelColor, levelBg;
    QString displayLevel = !sf.classificationLevel.isEmpty()
                               ? sf.classificationLevel : sf.severityLevel;
    QString levelUpper = displayLevel.toUpper();
    if (levelUpper == "CRITICAL")       { levelColor = "#C62828"; levelBg = "#FDECEA"; }
    else if (levelUpper == "SUSPICIOUS") { levelColor = "#E65100"; levelBg = "#FFF3E0"; }
    else if (levelUpper == "HIGH")       { levelColor = "#E65100"; levelBg = "#FFF3E0"; }
    else if (levelUpper == "ANOMALOUS")  { levelColor = "#F57F17"; levelBg = "#FFFDE7"; }
    else if (levelUpper == "MEDIUM")     { levelColor = "#F57F17"; levelBg = "#FFFDE7"; }
    else                                 { levelColor = "#2E7D32"; levelBg = "#E8F5E9"; }

    QString aiHtml;

    // "Why flagged?"
    if (!sf.keyIndicators.isEmpty()) {
        aiHtml += "<div style='background-color:#FFF3E0; border-radius:8px; padding:10px 14px;"
                  " margin:0 0 8px 0; border-left:4px solid #FF9800;'>";
        aiHtml += "<span style='font-size:13px; font-weight:bold; color:#E65100;'>"
                  "\xe2\x9a\xa0 Why was this flagged?</span><br>";
        int count = 0;
        for (const QString& ind : sf.keyIndicators) {
            if (count >= 3) break;
            aiHtml += "<span style='font-size:12px; color:#444;'>\xe2\x80\xa2 "
                      + ind + "</span><br>";
            ++count;
        }
        aiHtml += "</div>";
    }

    // Embedded AI section
    aiHtml += "<div style='background-color:#EDE7F6; border-radius:10px; padding:14px;"
              " margin:0 0 4px 0; border-left:4px solid #5C6BC0;'>";
    aiHtml += "<span style='font-size:14px; font-weight:bold; color:#1A237E;'>"
              "\xF0\x9F\xA7\xA0 Embedded AI Analysis</span>"
              "<span style='font-size:10px; color:#888; margin-left:6px;'>"
              "ONNX Anomaly Model</span><br><br>";

    if (!sf.aiSummary.isEmpty()) {
        aiHtml += "<span style='font-size:12px; color:#333; line-height:1.5;'>"
                  + sf.aiSummary + "</span><br>";
    } else {
        aiHtml += "<span style='font-size:12px; color:#999; font-style:italic;'>"
                  "No embedded AI summary available for this file.</span><br>";
    }

    if (sf.keyIndicators.size() > 3) {
        aiHtml += "<br><span style='font-size:11px; font-weight:bold; color:#555;'>"
                  "All indicators:</span><br>";
        for (const QString& ind : sf.keyIndicators) {
            aiHtml += "<span style='font-size:11px; color:#555;'>\xe2\x96\xb8 "
                      + ind + "</span><br>";
        }
    }

    aiHtml += "<br><span style='font-size:10px; color:#388E3C; font-weight:bold;'>"
              "\xe2\x9c\x93 Embedded AI: Active</span>";
    aiHtml += "</div>";

    // LLM section
    aiHtml += "<div style='background-color:#F5F9FF; border-radius:8px; padding:12px;"
              " margin:4px 0; border-left:3px solid #90CAF9;'>";
    aiHtml += "<span style='font-size:13px; font-weight:bold; color:#0D47A1;'>"
              "\xF0\x9F\x92\xAC LLM Explanation</span>"
              "<span style='font-size:10px; color:#888; margin-left:6px;'>"
              "Ollama / Llama3</span><br>";

    if (!sf.aiExplanation.isEmpty()) {
        aiHtml += "<br><span style='font-size:12px; color:#333; line-height:1.5;'>"
                  + sf.aiExplanation + "</span><br>";
        aiHtml += "<br><span style='font-size:10px; color:#1565C0; font-weight:bold;'>"
                  "\xe2\x9c\x93 LLM: Active</span>";
    } else if (m_llmPendingIndex >= 0) {
        // Still waiting for a response
        aiHtml += "<br><span style='font-size:12px; color:#1565C0; font-style:italic;'>"
                  "\xe2\x8f\xb3 Generating LLM explanation...</span><br>";
        aiHtml += "<br><span style='font-size:10px; color:#90CAF9;'>"
                  "LLM: Processing</span>";
    } else {
        aiHtml += "<br><span style='font-size:12px; color:#999; font-style:italic;'>"
                  "The LLM explanation service is not currently running. "
                  "The embedded AI analysis above provides the full assessment.</span><br>";
        aiHtml += "<br><span style='font-size:10px; color:#B0B0B0;'>"
                  "\xe2\x9c\x97 LLM: Unavailable</span>";
    }

    aiHtml += "</div>";
    detailsAILabel->setText(aiHtml);
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