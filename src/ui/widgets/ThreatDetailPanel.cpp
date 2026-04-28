// ============================================================================
// ThreatDetailPanel.cpp
// ============================================================================

#include "ThreatDetailPanel.h"
#include "../theme/DashboardTheme.h"

#include <QLabel>
#include <QPushButton>
#include <QTabWidget>
#include <QPlainTextEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QProgressBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QFrame>
#include <QFileInfo>
#include <QToolTip>

namespace {

QString severityHexFromClassification(const QString& classification)
{
    const QString c = classification.toUpper();
    if (c == "CRITICAL")    return Theme::Color::severityCritical;
    if (c == "SUSPICIOUS")  return Theme::Color::severityHigh;
    if (c == "ANOMALOUS")   return Theme::Color::severityMedium;
    return Theme::Color::accentBlue;
}

QString severityHexFromSeverity(const QString& severity)
{
    const QString s = severity.toUpper();
    if (s == "CRITICAL") return Theme::Color::severityCritical;
    if (s == "HIGH")      return Theme::Color::severityHigh;
    if (s == "MEDIUM")    return Theme::Color::severityMedium;
    if (s == "LOW")        return Theme::Color::severityLow;
    return Theme::Color::accentBlue;
}

QString prettyBytes(qint64 b)
{
    if (b >= 1LL << 30) return QString("%1 GB").arg(b / double(1LL << 30), 0, 'f', 1);
    if (b >= 1LL << 20) return QString("%1 MB").arg(b / double(1LL << 20), 0, 'f', 1);
    if (b >= 1LL << 10) return QString("%1 KB").arg(b / double(1LL << 10), 0, 'f', 1);
    return QString("%1 bytes").arg(b);
}

QString abbrevHash(const QString& hex, int head = 12, int tail = 8)
{
    if (hex.length() <= head + tail + 3) return hex;
    return hex.left(head) + "…" + hex.right(tail);
}

}  // anonymous

// ============================================================================
//  Construction + buildUi
// ============================================================================
ThreatDetailPanel::ThreatDetailPanel(QWidget* parent)
    : QFrame(parent)
{
    setObjectName("OdyThreatDetail");
    setAttribute(Qt::WA_StyledBackground, true);
    // Min/max range lets the QSplitter the panel sits inside drag-resize
    // within sane bounds. No setFixedWidth() — that would break the splitter.
    setMinimumWidth(360);
    setMaximumWidth(520);
    setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
    setStyleSheet(QString(
        "QFrame#OdyThreatDetail {"
        "  background-color: %1;"
        "  border-left: 1px solid %2;"
        "}"
    ).arg(Theme::Color::bgSecondary, Theme::Color::borderSubtle));

    buildUi();
    clear();
}

void ThreatDetailPanel::buildUi()
{
    auto* main = new QVBoxLayout(this);
    main->setContentsMargins(20, 16, 20, 16);
    main->setSpacing(12);

    // ── Header row: title + close ──────────────────────────────────────
    auto* topRow = new QHBoxLayout();
    auto* title = new QLabel("File Details", this);
    title->setStyleSheet(QString(
        "color: %1; font-size: 16px; font-weight: 700;")
            .arg(Theme::Color::textPrimary));
    topRow->addWidget(title);
    topRow->addStretch(1);

    m_closeBtn = new QPushButton(QString::fromUtf8("\xE2\x9C\x95"), this);   // ✕
    m_closeBtn->setCursor(Qt::PointingHandCursor);
    m_closeBtn->setFixedSize(28, 28);
    m_closeBtn->setStyleSheet(QString(
        "QPushButton { background: transparent; color: %1;"
        " border: 1px solid %2; border-radius: 6px; font-size: 12px; }"
        "QPushButton:hover { background-color: %3; color: white; }"
    ).arg(Theme::Color::textSecondary,
          Theme::Color::borderSubtle,
          Theme::Color::severityCritical));
    connect(m_closeBtn, &QPushButton::clicked,
            this, &ThreatDetailPanel::onCloseClicked);
    topRow->addWidget(m_closeBtn);
    main->addLayout(topRow);

    // ── File header card ───────────────────────────────────────────────
    auto* fileCard = new QFrame(this);
    fileCard->setObjectName("OdyFileCard");
    fileCard->setAttribute(Qt::WA_StyledBackground, true);
    fileCard->setStyleSheet(QString(
        "QFrame#OdyFileCard {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: %3px;"
        "}"
    ).arg(Theme::Color::bgCard,
          Theme::Color::borderSubtle)
     .arg(Theme::Size::cardRadius));

    auto* fc = new QHBoxLayout(fileCard);
    fc->setContentsMargins(14, 12, 14, 12);
    fc->setSpacing(12);

    m_iconLabel = new QLabel(QString::fromUtf8("\xE2\x96\xA4"), fileCard);  // ▤
    m_iconLabel->setFixedSize(48, 48);
    m_iconLabel->setAlignment(Qt::AlignCenter);
    m_iconLabel->setStyleSheet(QString(
        "QLabel { background-color: %1; color: white;"
        " font-size: 20px; border-radius: 10px; }")
            .arg(Theme::Color::accentBlue));
    fc->addWidget(m_iconLabel);

    auto* fcv = new QVBoxLayout();
    fcv->setContentsMargins(0, 0, 0, 0);
    fcv->setSpacing(2);

    auto* nameRow = new QHBoxLayout();
    nameRow->setSpacing(8);
    m_fileNameLabel = new QLabel("—", fileCard);
    m_fileNameLabel->setStyleSheet(QString(
        "color: %1; font-size: 14px; font-weight: 700;")
            .arg(Theme::Color::textPrimary));
    nameRow->addWidget(m_fileNameLabel);

    m_severityBadge = new QLabel("—", fileCard);
    m_severityBadge->setAlignment(Qt::AlignCenter);
    m_severityBadge->setStyleSheet(QString(
        "QLabel { color: white; background-color: %1;"
        " border-radius: 8px; padding: 2px 8px;"
        " font-size: 10px; font-weight: 700; }")
            .arg(Theme::Color::accentBlue));
    nameRow->addWidget(m_severityBadge);
    nameRow->addStretch(1);
    fcv->addLayout(nameRow);

    m_filePathLabel = new QLabel("", fileCard);
    m_filePathLabel->setStyleSheet(QString(
        "color: %1; font-size: 11px;")
            .arg(Theme::Color::textSecondary));
    m_filePathLabel->setWordWrap(false);
    m_filePathLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    fcv->addWidget(m_filePathLabel);

    m_fileMetaLabel = new QLabel("", fileCard);
    m_fileMetaLabel->setStyleSheet(QString(
        "color: %1; font-size: 11px;")
            .arg(Theme::Color::textSecondary));
    fcv->addWidget(m_fileMetaLabel);

    fc->addLayout(fcv, 1);
    main->addWidget(fileCard);

    // ── Tabs ───────────────────────────────────────────────────────────
    m_tabs = new QTabWidget(this);
    m_tabs->setStyleSheet(QString(
        "QTabWidget::pane { border: none; background: transparent; }"
        "QTabBar::tab {"
        "  background: transparent; color: %1;"
        "  padding: 8px 14px; margin-right: 4px;"
        "  border-bottom: 2px solid transparent;"
        "  font-size: 12px; font-weight: 600;"
        "}"
        "QTabBar::tab:hover { color: %2; }"
        "QTabBar::tab:selected {"
        "  color: %2; border-bottom: 2px solid %3;"
        "}"
    ).arg(Theme::Color::textSecondary,
          Theme::Color::textPrimary,
          Theme::Color::accentBlue));

    m_tabs->addTab(buildOverviewTab(),   "Overview");
    m_tabs->addTab(buildAiAnalysisTab(), "AI Analysis");
    m_tabs->addTab(buildIndicatorsTab(), "Indicators");
    m_tabs->addTab(buildDetailsTab(),    "Details");
    main->addWidget(m_tabs, 1);

    // ── Footer action buttons ──────────────────────────────────────────
    auto* actionsBar = new QHBoxLayout();
    actionsBar->setSpacing(8);

    auto buildActionBtn = [this](const QString& label,
                                  const QString& bg) -> QPushButton* {
        auto* b = new QPushButton(label, this);
        b->setCursor(Qt::PointingHandCursor);
        b->setEnabled(false);
        b->setToolTip("Coming soon — action wiring lands in a future release");
        b->setStyleSheet(QString(
            "QPushButton {"
            "  background-color: %1; color: white; border: none;"
            "  border-radius: 8px; padding: 8px 14px;"
            "  font-size: 12px; font-weight: 600;"
            "}"
            "QPushButton:disabled { background-color: %2; color: %3; }"
        ).arg(bg)
         .arg(Theme::Color::bgPrimary)
         .arg(Theme::Color::textMuted));
        return b;
    };

    m_quarantineBtn = buildActionBtn(QString::fromUtf8("\xF0\x9F\x94\x92  Quarantine"),
                                      Theme::Color::severityHigh);
    m_deleteBtn     = buildActionBtn(QString::fromUtf8("\xF0\x9F\x97\x91  Delete"),
                                      Theme::Color::severityCritical);
    m_ignoreBtn     = buildActionBtn(QString::fromUtf8("\xE2\x9C\x95  Ignore"),
                                      Theme::Color::accentBlueSoft);

    actionsBar->addWidget(m_quarantineBtn, 1);
    actionsBar->addWidget(m_deleteBtn, 1);
    actionsBar->addWidget(m_ignoreBtn, 1);
    main->addLayout(actionsBar);
}

// ============================================================================
//  Tab builders
// ============================================================================
QWidget* ThreatDetailPanel::buildOverviewTab()
{
    auto* w = new QWidget();
    w->setStyleSheet("background: transparent;");
    auto* v = new QVBoxLayout(w);
    v->setContentsMargins(0, 12, 0, 0);
    v->setSpacing(14);

    // ── Polish.6 — "Why flagged" prominent call-out ────────────────────
    // First thing the analyst sees on Overview. Severity-tinted left
    // border keeps it visually anchored even when the panel is narrow.
    m_whyFlaggedCard = new QFrame(w);
    m_whyFlaggedCard->setObjectName("OdyWhyFlagged");
    m_whyFlaggedCard->setAttribute(Qt::WA_StyledBackground, true);
    m_whyFlaggedCard->setStyleSheet(QString(
        "QFrame#OdyWhyFlagged {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-left: 3px solid %3;"
        "  border-radius: 8px;"
        "}"
    ).arg(Theme::Color::bgPrimary,
          Theme::Color::borderSubtle,
          Theme::Color::severityCritical));
    auto* wfLayout = new QVBoxLayout(m_whyFlaggedCard);
    wfLayout->setContentsMargins(12, 10, 12, 10);
    wfLayout->setSpacing(4);

    auto* wfTitle = new QLabel(
        QString::fromUtf8("\xE2\x9A\xA0  Why flagged?"), m_whyFlaggedCard);
    wfTitle->setStyleSheet(QString(
        "color: %1; %2")
            .arg(Theme::Color::severityCritical)
            .arg(Theme::Type::qss(Theme::Type::Caption,
                                    Theme::Type::WeightBold)));
    wfLayout->addWidget(wfTitle);

    m_whyFlaggedLabel = new QLabel("—", m_whyFlaggedCard);
    m_whyFlaggedLabel->setWordWrap(true);
    m_whyFlaggedLabel->setTextFormat(Qt::RichText);
    m_whyFlaggedLabel->setStyleSheet(QString(
        "color: %1; %2 line-height: 1.55;")
            .arg(Theme::Color::textPrimary)
            .arg(Theme::Type::qss(Theme::Type::Body)));
    wfLayout->addWidget(m_whyFlaggedLabel);
    v->addWidget(m_whyFlaggedCard);

    // AI Summary
    auto* sumTitle = new QLabel(QString::fromUtf8("\xE2\x84\xB9  AI Summary"), w);
    sumTitle->setStyleSheet(QString(
        "color: %1; %2")
            .arg(Theme::Color::accentBlue)
            .arg(Theme::Type::qss(Theme::Type::Caption,
                                    Theme::Type::WeightBold)));
    v->addWidget(sumTitle);

    m_aiSummaryLabel = new QLabel("—", w);
    m_aiSummaryLabel->setWordWrap(true);
    m_aiSummaryLabel->setStyleSheet(QString(
        "color: %1; %2 line-height: 1.5;")
            .arg(Theme::Color::textPrimary)
            .arg(Theme::Type::qss(Theme::Type::Body)));
    v->addWidget(m_aiSummaryLabel);

    // Threat Score
    auto* scoreTitle = new QLabel("Threat Score", w);
    scoreTitle->setStyleSheet(QString(
        "color: %1; font-size: 11px; font-weight: 600;"
        " padding-top: 6px;")
            .arg(Theme::Color::textSecondary));
    v->addWidget(scoreTitle);

    auto* scoreRow = new QHBoxLayout();
    m_scoreBar = new QProgressBar(w);
    m_scoreBar->setRange(0, 1000);
    m_scoreBar->setTextVisible(false);
    m_scoreBar->setFixedHeight(6);
    m_scoreBar->setStyleSheet(QString(
        "QProgressBar { background-color: %1; border-radius: 3px; }"
        "QProgressBar::chunk { background-color: %2; border-radius: 3px; }"
    ).arg(Theme::Color::bgPrimary,
          Theme::Color::severityCritical));
    scoreRow->addWidget(m_scoreBar, 1);

    m_scoreText = new QLabel("—", w);
    m_scoreText->setAlignment(Qt::AlignRight);
    m_scoreText->setStyleSheet(QString(
        "color: %1; font-size: 11px; font-weight: 600;"
        " font-family: monospace;")
            .arg(Theme::Color::textPrimary));
    m_scoreText->setMinimumWidth(80);
    scoreRow->addWidget(m_scoreText);
    v->addLayout(scoreRow);

    // LLM excerpt
    auto* llmTitle = new QLabel(
        QString::fromUtf8("\xF0\x9F\x92\xAC  AI Explanation ")
            + "<span style='color:" + QString(Theme::Color::textMuted)
            + "; font-size:10px; font-weight: 400;'>(Powered by Ollama)</span>", w);
    llmTitle->setStyleSheet(QString(
        "color: %1; font-size: 12px; font-weight: 700; padding-top: 4px;")
            .arg(Theme::Color::accentBlue));
    llmTitle->setTextFormat(Qt::RichText);
    v->addWidget(llmTitle);

    m_overviewLlm = new QPlainTextEdit(w);
    m_overviewLlm->setReadOnly(true);
    m_overviewLlm->setMaximumHeight(140);
    m_overviewLlm->setStyleSheet(QString(
        "QPlainTextEdit {"
        "  background-color: %1; color: %2;"
        "  border: 1px solid %3; border-radius: 6px;"
        "  padding: 8px; font-size: 11px;"
        "}"
    ).arg(Theme::Color::bgPrimary,
          Theme::Color::textPrimary,
          Theme::Color::borderSubtle));
    v->addWidget(m_overviewLlm);

    // Recommended Actions (top 3)
    auto* actTitle = new QLabel("Recommended Actions", w);
    actTitle->setStyleSheet(QString(
        "color: %1; font-size: 11px; font-weight: 600;"
        " padding-top: 4px;")
            .arg(Theme::Color::textSecondary));
    v->addWidget(actTitle);

    m_actionsLabel = new QLabel("—", w);
    m_actionsLabel->setWordWrap(true);
    m_actionsLabel->setTextFormat(Qt::RichText);
    m_actionsLabel->setStyleSheet(QString(
        "color: %1; font-size: 12px; line-height: 1.6;")
            .arg(Theme::Color::textPrimary));
    v->addWidget(m_actionsLabel);

    // Compact hash row
    auto* hashRow = new QHBoxLayout();
    auto* hashLabel = new QLabel("SHA-256", w);
    hashLabel->setStyleSheet(QString(
        "color: %1; font-size: 11px; font-weight: 600;")
            .arg(Theme::Color::textSecondary));
    hashLabel->setMinimumWidth(64);
    hashRow->addWidget(hashLabel);

    m_sha256Compact = new QLabel("—", w);
    m_sha256Compact->setStyleSheet(QString(
        "color: %1; font-size: 10px; font-family: monospace;")
            .arg(Theme::Color::textMuted));
    m_sha256Compact->setTextInteractionFlags(Qt::TextSelectableByMouse);
    hashRow->addWidget(m_sha256Compact, 1);
    v->addLayout(hashRow);

    v->addStretch(1);
    return w;
}

QWidget* ThreatDetailPanel::buildAiAnalysisTab()
{
    auto* w = new QWidget();
    w->setStyleSheet("background: transparent;");
    auto* v = new QVBoxLayout(w);
    v->setContentsMargins(0, 12, 0, 0);
    v->setSpacing(10);

    // Embedded AI summary (always present from Phase 1 calibration pipeline)
    auto* embedHeader = new QLabel("Embedded AI Analysis", w);
    embedHeader->setStyleSheet(QString(
        "color: %1; font-size: 12px; font-weight: 700;")
            .arg(Theme::Color::accentBlue));
    v->addWidget(embedHeader);

    m_aiSummaryFull = new QLabel("—", w);
    m_aiSummaryFull->setWordWrap(true);
    m_aiSummaryFull->setStyleSheet(QString(
        "color: %1; font-size: 12px; line-height: 1.5;")
            .arg(Theme::Color::textPrimary));
    v->addWidget(m_aiSummaryFull);

    // LLM full explanation
    auto* llmHeader = new QLabel("LLM Explanation", w);
    llmHeader->setStyleSheet(QString(
        "color: %1; font-size: 12px; font-weight: 700; padding-top: 6px;")
            .arg(Theme::Color::accentBlue));
    v->addWidget(llmHeader);

    m_llmFull = new QPlainTextEdit(w);
    m_llmFull->setReadOnly(true);
    m_llmFull->setStyleSheet(QString(
        "QPlainTextEdit {"
        "  background-color: %1; color: %2;"
        "  border: 1px solid %3; border-radius: 6px;"
        "  padding: 10px; font-size: 12px;"
        "}"
    ).arg(Theme::Color::bgPrimary,
          Theme::Color::textPrimary,
          Theme::Color::borderSubtle));
    v->addWidget(m_llmFull, 1);

    m_modelInfoLabel = new QLabel("", w);
    m_modelInfoLabel->setStyleSheet(QString(
        "color: %1; font-size: 10px; padding-top: 4px;")
            .arg(Theme::Color::textMuted));
    v->addWidget(m_modelInfoLabel);

    return w;
}

QWidget* ThreatDetailPanel::buildIndicatorsTab()
{
    auto* w = new QWidget();
    w->setStyleSheet("background: transparent;");
    auto* v = new QVBoxLayout(w);
    v->setContentsMargins(0, 12, 0, 0);
    v->setSpacing(10);

    auto* indHeader = new QLabel("Key Indicators", w);
    indHeader->setStyleSheet(QString(
        "color: %1; font-size: 12px; font-weight: 700;")
            .arg(Theme::Color::accentBlue));
    v->addWidget(indHeader);

    auto listQss = QString(
        "QListWidget {"
        "  background-color: %1; color: %2;"
        "  border: 1px solid %3; border-radius: 6px;"
        "  padding: 4px; font-size: 11px;"
        "}"
        "QListWidget::item { padding: 4px 6px;"
        "  border-bottom: 1px solid %3; }"
    ).arg(Theme::Color::bgPrimary,
          Theme::Color::textPrimary,
          Theme::Color::borderSubtle);

    m_indicatorsList = new QListWidget(w);
    m_indicatorsList->setStyleSheet(listQss);
    m_indicatorsList->setFrameShape(QFrame::NoFrame);
    v->addWidget(m_indicatorsList, 1);

    auto* yaraHeader = new QLabel("YARA Matches", w);
    yaraHeader->setStyleSheet(QString(
        "color: %1; font-size: 12px; font-weight: 700; padding-top: 6px;")
            .arg(Theme::Color::accentBlue));
    v->addWidget(yaraHeader);

    m_yaraFamilyLabel = new QLabel("", w);
    m_yaraFamilyLabel->setStyleSheet(QString(
        "color: %1; font-size: 11px;")
            .arg(Theme::Color::textSecondary));
    v->addWidget(m_yaraFamilyLabel);

    m_yaraList = new QListWidget(w);
    m_yaraList->setStyleSheet(listQss);
    m_yaraList->setFrameShape(QFrame::NoFrame);
    m_yaraList->setMaximumHeight(120);
    v->addWidget(m_yaraList);

    return w;
}

QWidget* ThreatDetailPanel::buildDetailsTab()
{
    auto* w = new QWidget();
    w->setStyleSheet("background: transparent;");
    auto* v = new QVBoxLayout(w);
    v->setContentsMargins(0, 12, 0, 0);
    v->setSpacing(8);

    auto rowQss = QString(
        "color: %1; font-size: 11px;").arg(Theme::Color::textPrimary);

    auto headerQss = QString(
        "color: %1; font-size: 11px; font-weight: 600;")
            .arg(Theme::Color::textSecondary);

    auto addPair = [v, &rowQss, &headerQss](const QString& title,
                                              QLabel*& valueOut) {
        auto* h = new QLabel(title);
        h->setStyleSheet(headerQss);
        v->addWidget(h);
        valueOut = new QLabel("—");
        valueOut->setStyleSheet(rowQss);
        valueOut->setWordWrap(true);
        valueOut->setTextInteractionFlags(Qt::TextSelectableByMouse);
        v->addWidget(valueOut);
    };

    addPair("Path",            m_detPath);
    addPair("Classification",  m_detClassification);
    addPair("SHA-256",         m_detSha256);
    addPair("Size",            m_detSize);
    addPair("Last Modified",   m_detModified);
    addPair("Code Signing",    m_detSigning);
    addPair("Reputation",      m_detReputation);

    // Override SHA-256 with monospace font
    m_detSha256->setStyleSheet(QString(
        "color: %1; font-size: 10px; font-family: monospace;")
            .arg(Theme::Color::textPrimary));

    v->addStretch(1);
    return w;
}

// ============================================================================
//  Public API
// ============================================================================
void ThreatDetailPanel::clear()
{
    m_currentPath.clear();

    m_fileNameLabel->setText("No file selected");
    m_filePathLabel->clear();
    m_fileMetaLabel->clear();
    m_severityBadge->setText("—");
    m_severityBadge->setStyleSheet(QString(
        "QLabel { color: white; background-color: %1;"
        " border-radius: 8px; padding: 2px 8px;"
        " font-size: 10px; font-weight: 700; }")
            .arg(Theme::Color::accentBlueSoft));

    m_aiSummaryLabel->setText("—");
    m_scoreBar->setValue(0);
    m_scoreText->setText("—");
    m_overviewLlm->clear();
    m_actionsLabel->setText("—");
    m_sha256Compact->setText("—");

    m_aiSummaryFull->setText("—");
    m_llmFull->clear();
    m_modelInfoLabel->clear();

    m_indicatorsList->clear();
    m_yaraList->clear();
    m_yaraFamilyLabel->clear();

    m_detPath->setText("—");
    m_detClassification->setText("—");
    m_detSha256->setText("—");
    m_detSize->setText("—");
    m_detModified->setText("—");
    m_detSigning->setText("—");
    m_detReputation->setText("—");
}

void ThreatDetailPanel::setFile(const SuspiciousFile& sf)
{
    m_currentPath = sf.filePath;

    // ── Header card ────────────────────────────────────────────────────
    m_fileNameLabel->setText(sf.fileName.isEmpty() ? "(no name)" : sf.fileName);
    QString shortPath = sf.filePath;
    if (shortPath.length() > 60) shortPath = "…" + shortPath.right(58);
    m_filePathLabel->setText(shortPath);
    m_fileMetaLabel->setText(QString("%1 • Modified: %2")
                                .arg(prettyBytes(sf.sizeBytes))
                                .arg(sf.lastModified.isValid()
                                        ? sf.lastModified.toString("yyyy-MM-dd hh:mm")
                                        : QStringLiteral("?")));

    // Severity badge
    const QString cls = sf.classificationLevel.isEmpty()
                            ? sf.severityLevel : sf.classificationLevel;
    const QString hex = severityHexFromClassification(sf.classificationLevel);
    m_severityBadge->setText(cls.isEmpty() ? "—" : cls.toUpper());
    m_severityBadge->setStyleSheet(QString(
        "QLabel { color: white; background-color: %1;"
        " border-radius: 8px; padding: 2px 8px;"
        " font-size: 10px; font-weight: 700; }")
            .arg(hex));

    // Icon background tint for high-severity files
    m_iconLabel->setStyleSheet(QString(
        "QLabel { background-color: %1; color: white;"
        " font-size: 20px; border-radius: 10px; }")
            .arg(hex));

    populateOverview(sf);
    populateAiAnalysis(sf);
    populateIndicators(sf);
    populateDetails(sf);
}

// ============================================================================
//  Tab population
// ============================================================================
void ThreatDetailPanel::populateOverview(const SuspiciousFile& sf)
{
    // Polish.6 — populate the "Why flagged" call-out at the top.
    // Use the top key indicators if present; fall back to the legacy
    // reason string. Border tint follows the file's severity.
    const QString sevHex = severityHexFromClassification(sf.classificationLevel);
    if (m_whyFlaggedCard) {
        m_whyFlaggedCard->setStyleSheet(QString(
            "QFrame#OdyWhyFlagged {"
            "  background-color: %1;"
            "  border: 1px solid %2;"
            "  border-left: 3px solid %3;"
            "  border-radius: 8px;"
            "}"
        ).arg(Theme::Color::bgPrimary,
              Theme::Color::borderSubtle,
              sevHex));
    }
    QString whyHtml;
    if (!sf.keyIndicators.isEmpty()) {
        for (int i = 0; i < qMin(3, int(sf.keyIndicators.size())); ++i) {
            whyHtml += QString::fromUtf8("\xE2\x80\xA2 ")
                        + sf.keyIndicators[i].toHtmlEscaped() + "<br>";
        }
    } else if (!sf.reason.isEmpty()) {
        whyHtml = sf.reason.toHtmlEscaped();
    } else {
        whyHtml = "No specific indicators captured.";
    }
    m_whyFlaggedLabel->setText(whyHtml);

    // AI Summary (embedded)
    m_aiSummaryLabel->setText(sf.aiSummary.isEmpty()
                               ? "No AI summary available."
                               : sf.aiSummary);

    // Threat Score: prefer confidencePct (0-100), fall back to anomalyScore
    float pct = sf.confidencePct;
    if (pct <= 0.0f && sf.anomalyScore > 0.0f) pct = sf.anomalyScore * 100.0f;
    m_scoreBar->setValue(static_cast<int>(pct * 10.0f));
    m_scoreText->setText(QString("%1 / 1.00")
                            .arg(sf.anomalyScore, 0, 'f', 2));

    QString barColor = severityHexFromClassification(sf.classificationLevel);
    m_scoreBar->setStyleSheet(QString(
        "QProgressBar { background-color: %1; border-radius: 3px; }"
        "QProgressBar::chunk { background-color: %2; border-radius: 3px; }"
    ).arg(Theme::Color::bgPrimary, barColor));

    // LLM excerpt
    if (!sf.aiExplanation.isEmpty()) {
        m_overviewLlm->setPlainText(sf.aiExplanation);
    } else {
        m_overviewLlm->setPlainText(
            sf.llmAvailable
                ? "LLM explanation requested — refresh in a moment."
                : "LLM (Ollama) not available. The embedded AI summary above "
                  "provides the full assessment.");
    }

    // Recommended actions
    if (sf.recommendedActions.isEmpty()) {
        m_actionsLabel->setText("No recommended actions.");
    } else {
        QString html;
        for (int i = 0; i < qMin(3, int(sf.recommendedActions.size())); ++i) {
            html += QString("\xE2\x80\xA2 %1<br>")
                       .arg(sf.recommendedActions[i].toHtmlEscaped());
        }
        m_actionsLabel->setText(html);
    }

    // Hash compact
    m_sha256Compact->setText(sf.sha256.isEmpty()
                              ? "(not computed)"
                              : abbrevHash(sf.sha256));
}

void ThreatDetailPanel::populateAiAnalysis(const SuspiciousFile& sf)
{
    m_aiSummaryFull->setText(sf.aiSummary.isEmpty()
                              ? "No AI summary available."
                              : sf.aiSummary);

    if (!sf.aiExplanation.isEmpty()) {
        m_llmFull->setPlainText(sf.aiExplanation);
        m_modelInfoLabel->setText(
            sf.llmAvailable
                ? QString::fromUtf8("\xE2\x9C\x93 LLM Active \xE2\x80\xA2 "
                                      "Ollama / Llama3")
                : "LLM cached.");
    } else {
        m_llmFull->setPlainText(
            "The Ollama LLM service is not currently providing an "
            "explanation for this file. The embedded ONNX anomaly model's "
            "summary above is the authoritative assessment for this run.\n\n"
            "To enable rich LLM explanations, run `ollama serve` and ensure "
            "the model named in your config is pulled (e.g. `ollama pull llama3`).");
        m_modelInfoLabel->setText(QString::fromUtf8(
            "\xE2\x9C\x97 LLM Unavailable \xE2\x80\xA2 "
            "Embedded ONNX model still active"));
    }
}

void ThreatDetailPanel::populateIndicators(const SuspiciousFile& sf)
{
    m_indicatorsList->clear();
    if (sf.keyIndicators.isEmpty()) {
        auto* item = new QListWidgetItem("(no key indicators)");
        item->setForeground(QColor(Theme::Color::textMuted));
        item->setFlags(Qt::ItemIsEnabled);
        m_indicatorsList->addItem(item);
    } else {
        for (const QString& ind : sf.keyIndicators) {
            QListWidgetItem* item = new QListWidgetItem("• " + ind);
            // [Expected] tagged indicators get muted color
            if (ind.contains("[Expected]"))
                item->setForeground(QColor(Theme::Color::textMuted));
            else
                item->setForeground(QColor(Theme::Color::textPrimary));
            m_indicatorsList->addItem(item);
        }
    }

    m_yaraList->clear();
    if (sf.yaraMatches.isEmpty()) {
        auto* item = new QListWidgetItem("(no YARA rules fired)");
        item->setForeground(QColor(Theme::Color::textMuted));
        item->setFlags(Qt::ItemIsEnabled);
        m_yaraList->addItem(item);
        m_yaraFamilyLabel->setText("");
    } else {
        for (const QString& rule : sf.yaraMatches) {
            QListWidgetItem* item = new QListWidgetItem(rule);
            item->setForeground(QColor(Theme::Color::severityCritical));
            m_yaraList->addItem(item);
        }
        QString summary;
        if (!sf.yaraFamily.isEmpty())
            summary += QString("Family: <b style='color:%1;'>%2</b>")
                          .arg(Theme::Color::severityCritical, sf.yaraFamily);
        if (!sf.yaraSeverity.isEmpty()) {
            if (!summary.isEmpty()) summary += " • ";
            summary += QString("Severity: <b>%1</b>").arg(sf.yaraSeverity);
        }
        m_yaraFamilyLabel->setText(summary);
        m_yaraFamilyLabel->setTextFormat(Qt::RichText);
    }
}

void ThreatDetailPanel::populateDetails(const SuspiciousFile& sf)
{
    m_detPath->setText(sf.filePath.isEmpty() ? "—" : sf.filePath);
    m_detClassification->setText(QString("%1 / %2 (score %3, threshold %4)")
                                    .arg(sf.classificationLevel.isEmpty() ? "—" : sf.classificationLevel,
                                         sf.severityLevel.isEmpty()        ? "—" : sf.severityLevel)
                                    .arg(sf.anomalyScore,     0, 'f', 3)
                                    .arg(sf.anomalyThreshold, 0, 'f', 3));

    m_detSha256->setText(sf.sha256.isEmpty() ? "(not computed)" : sf.sha256);
    m_detSize->setText(QString("%1 (%2 bytes)")
                          .arg(prettyBytes(sf.sizeBytes))
                          .arg(sf.sizeBytes));
    m_detModified->setText(sf.lastModified.isValid()
                              ? sf.lastModified.toString(Qt::ISODate)
                              : "—");

    QString sgnText;
    QString sgnColor = Theme::Color::textPrimary;
    switch (sf.signingStatus) {
        case 2: sgnText = "Signed (trusted)";   sgnColor = Theme::Color::severitySafe; break;
        case 1: sgnText = "Signed (untrusted)"; sgnColor = Theme::Color::severityMedium; break;
        case 0: sgnText = "UNSIGNED";            sgnColor = Theme::Color::severityCritical; break;
        default: sgnText = "Unknown / not checked"; break;
    }
    if (!sf.signerId.isEmpty())
        sgnText += " — " + sf.signerId;
    m_detSigning->setText(QString("<span style='color:%1;'>%2</span>")
                              .arg(sgnColor, sgnText.toHtmlEscaped()));
    m_detSigning->setTextFormat(Qt::RichText);

    QString rep;
    if (sf.reputationFamily.isEmpty()) {
        rep = "(not in reputation database)";
    } else {
        rep = QString("Family: <b>%1</b>").arg(sf.reputationFamily);
        if (!sf.reputationSource.isEmpty())
            rep += QString(" • source: %1").arg(sf.reputationSource);
        if (sf.reputationPrevalence > 0)
            rep += QString(" • seen %1\xC3\x97 on this host")
                       .arg(sf.reputationPrevalence);
    }
    m_detReputation->setText(rep);
    m_detReputation->setTextFormat(Qt::RichText);
}

void ThreatDetailPanel::onCloseClicked()
{
    emit closeRequested();
}
