// ============================================================================
// ResultsPage.cpp
// ============================================================================

#include "ResultsPage.h"
#include "../theme/DashboardTheme.h"
#include "../widgets/StatCard.h"
#include "../widgets/ThreatRow.h"
#include "../widgets/DetailSection.h"

// Phase 5 — Response & Control Layer
#include "response/ResponseManagerSingleton.h"
#include "response/ResponseManager.h"
#include "response/ResponseTypes.h"

#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QComboBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QScrollArea>
#include <QProgressBar>
#include <QPlainTextEdit>
#include <QFileInfo>
#include <QDateTime>
#include <QRegularExpression>
#include <QMessageBox>

namespace {

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

QString sourceForFinding(const SuspiciousFile& sf)
{
    if (!sf.cveId.isEmpty()) return "NVD";
    if (sf.category.contains("YARA", Qt::CaseInsensitive)) return "YARA";
    if (sf.category.contains("Hash", Qt::CaseInsensitive)) return "Hash DB";
    return "AI Model";
}

}  // anonymous

// ============================================================================
//  Construction
// ============================================================================
ResultsPage::ResultsPage(QWidget* parent)
    : QWidget(parent)
{
    setStyleSheet(QString("background-color: %1;")
                      .arg(Theme::Color::bgPrimary));
    buildUi();
    rebuildVisibleRows();      // shows the empty-state on first paint
    recomputeStats();
}

QString ResultsPage::severityFromFinding(const SuspiciousFile& sf)
{
    const QString c = sf.classificationLevel.toUpper();
    if (c == "CRITICAL")            return "critical";
    if (c == "SUSPICIOUS")          return "suspicious";
    if (c == "ANOMALOUS")           return "needs-review";
    if (c == "CLEAN")                return "clean";
    // Legacy fallbacks
    const QString s = sf.severityLevel.toUpper();
    if (s == "CRITICAL")  return "critical";
    if (s == "HIGH")       return "suspicious";
    if (s == "MEDIUM")     return "needs-review";
    if (s == "LOW")        return "needs-review";
    return "needs-review";
}

void ResultsPage::buildUi()
{
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->setSpacing(0);

    auto* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setStyleSheet("background: transparent;");
    outer->addWidget(scroll);

    auto* content = new QWidget();
    content->setStyleSheet("background: transparent;");
    auto* main = new QVBoxLayout(content);
    main->setContentsMargins(32, 28, 32, 28);
    main->setSpacing(24);

    // ── Header row ─────────────────────────────────────────────────────
    auto* headerRow = new QHBoxLayout();
    headerRow->setSpacing(16);

    auto* titleCol = new QVBoxLayout();
    titleCol->setSpacing(2);
    m_title = new QLabel("Results", content);
    m_title->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent; }")
            .arg(Theme::Color::textPrimary)
            .arg(Theme::Type::qss(Theme::Type::Display,
                                    Theme::Type::WeightBold)));
    titleCol->addWidget(m_title);

    m_subtitle = new QLabel("Review and analyze detected threats", content);
    m_subtitle->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent; }")
            .arg(Theme::Color::textSecondary)
            .arg(Theme::Type::qss(Theme::Type::Body)));
    titleCol->addWidget(m_subtitle);
    headerRow->addLayout(titleCol);
    headerRow->addStretch(1);

    m_exportBtn = new QPushButton("Export Results", content);
    m_exportBtn->setCursor(Qt::PointingHandCursor);
    m_exportBtn->setStyleSheet(QString(
        "QPushButton {"
        "  background-color: %1; color: %2;"
        "  border: 1px solid %3; border-radius: 8px;"
        "  padding: 8px 18px; %4"
        "}"
        "QPushButton:hover { background-color: %5; color: white; }"
    ).arg(Theme::Color::bgCard,
          Theme::Color::textPrimary,
          Theme::Color::borderSubtle)
     .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi))
     .arg(Theme::Color::accentBlueSoft));
    connect(m_exportBtn, &QPushButton::clicked,
            this, &ResultsPage::exportRequested);
    headerRow->addWidget(m_exportBtn, 0, Qt::AlignTop);
    main->addLayout(headerRow);

    // ── KPI cards (4 equal) ───────────────────────────────────────────
    auto* kpiRow = new QHBoxLayout();
    kpiRow->setSpacing(16);

    m_kpiFilesScanned = new StatCard(content);
    m_kpiFilesScanned->setTone(StatCard::Info);
    m_kpiFilesScanned->setTitle("FILES SCANNED");
    m_kpiFilesScanned->setValue("0");
    m_kpiFilesScanned->setSubtitle("Total files analyzed");
    m_kpiFilesScanned->setIcon("");           // strict: no glyph in cards
    kpiRow->addWidget(m_kpiFilesScanned, 1);

    m_kpiSuspicious = new StatCard(content);
    m_kpiSuspicious->setTone(StatCard::Critical);
    m_kpiSuspicious->setTitle("SUSPICIOUS");
    m_kpiSuspicious->setValue("0");
    m_kpiSuspicious->setSubtitle("Require attention");
    m_kpiSuspicious->setIcon("");
    kpiRow->addWidget(m_kpiSuspicious, 1);

    m_kpiNeedsReview = new StatCard(content);
    m_kpiNeedsReview->setTone(StatCard::Warning);
    m_kpiNeedsReview->setTitle("NEEDS REVIEW");
    m_kpiNeedsReview->setValue("0");
    m_kpiNeedsReview->setSubtitle("Manual review");
    m_kpiNeedsReview->setIcon("");
    kpiRow->addWidget(m_kpiNeedsReview, 1);

    m_kpiAvgScore = new StatCard(content);
    m_kpiAvgScore->setTone(StatCard::Safe);
    m_kpiAvgScore->setTitle("AVG THREAT SCORE");
    m_kpiAvgScore->setValue("0.00 / 1.00");
    m_kpiAvgScore->setSubtitle("Average across all");
    m_kpiAvgScore->setIcon("");
    kpiRow->addWidget(m_kpiAvgScore, 1);

    main->addLayout(kpiRow);

    // ── Filter row ─────────────────────────────────────────────────────
    auto* filterRow = new QHBoxLayout();
    filterRow->setSpacing(12);

    m_searchInput = new QLineEdit(content);
    m_searchInput->setPlaceholderText("Search threats, CVE, file...");
    m_searchInput->setMinimumHeight(40);
    m_searchInput->setStyleSheet(QString(
        "QLineEdit {"
        "  background-color: %1; color: %2;"
        "  border: 1px solid %3; border-radius: 8px;"
        "  padding: 8px 14px; %4"
        "}"
        "QLineEdit:focus { border-color: %5; }"
    )
    .arg(Theme::Color::bgCard, Theme::Color::textPrimary,
         Theme::Color::borderSubtle)
    .arg(Theme::Type::qss(Theme::Type::Body))
    .arg(Theme::Color::accentBlue));
    connect(m_searchInput, &QLineEdit::textChanged,
            this, &ResultsPage::onSearchChanged);
    filterRow->addWidget(m_searchInput, 1);

    auto styleCombo = [](QComboBox* cb) {
        cb->setMinimumHeight(40);
        cb->setMinimumWidth(180);
        cb->setStyleSheet(QString(
            "QComboBox {"
            "  background-color: %1; color: %2;"
            "  border: 1px solid %3; border-radius: 8px;"
            "  padding: 8px 14px; %4"
            "}"
            "QComboBox::drop-down { border: none; width: 24px; }"
            "QComboBox QAbstractItemView {"
            "  background-color: %1; color: %2;"
            "  selection-background-color: %5;"
            "  border: 1px solid %3;"
            "}"
        )
        .arg(Theme::Color::bgCard, Theme::Color::textPrimary,
             Theme::Color::borderSubtle)
        .arg(Theme::Type::qss(Theme::Type::Body))
        .arg(Theme::Color::accentBlueSoft));
    };

    m_severityFilter = new QComboBox(content);
    m_severityFilter->addItems({ "All Severities",
                                   "Critical",
                                   "Suspicious",
                                   "Needs Review" });
    styleCombo(m_severityFilter);
    connect(m_severityFilter, &QComboBox::currentTextChanged,
            this, &ResultsPage::onFilterChanged);
    filterRow->addWidget(m_severityFilter, 0);

    m_sourceFilter = new QComboBox(content);
    m_sourceFilter->addItems({ "All Sources", "AI Model", "NVD",
                                 "YARA", "Hash DB" });
    styleCombo(m_sourceFilter);
    connect(m_sourceFilter, &QComboBox::currentTextChanged,
            this, &ResultsPage::onFilterChanged);
    filterRow->addWidget(m_sourceFilter, 0);

    main->addLayout(filterRow);

    // ── Main split: list (left) | detail panel (right) ────────────────
    auto* split = new QHBoxLayout();
    split->setSpacing(20);

    // ── Left column: column headers floating above row stack ──────────
    // No outer card border — rows ARE the cards. Spacing between them
    // does the visual separation (Linear/Vercel pattern).
    m_listCard = new QFrame(content);
    m_listCard->setObjectName("OdyResultsListContainer");
    m_listCard->setAttribute(Qt::WA_StyledBackground, true);
    m_listCard->setStyleSheet(
        "QFrame#OdyResultsListContainer { background: transparent; border: none; }");

    auto* listLayout = new QVBoxLayout(m_listCard);
    listLayout->setContentsMargins(0, 0, 0, 0);
    listLayout->setSpacing(0);

    // ── Column headers (free-floating, single thin separator below) ───
    auto* headerBar = new QFrame(m_listCard);
    headerBar->setStyleSheet(QString(
        "QFrame { background: transparent;"
        " border-bottom: 1px solid %1; }").arg(Theme::Color::borderSubtle));
    auto* headerLayout = new QHBoxLayout(headerBar);
    headerLayout->setContentsMargins(20, 12, 20, 12);
    headerLayout->setSpacing(20);
    auto headerStyle = QString(
        "QLabel { color: %1; %2 background: transparent;"
        " letter-spacing: 0.6px; }")
            .arg(Theme::Color::textSecondary)
            .arg(Theme::Type::qss(Theme::Type::Caption,
                                    Theme::Type::WeightSemi));
    auto buildHeader = [&headerStyle](const QString& t, int width) {
        auto* l = new QLabel(t.toUpper());
        l->setStyleSheet(headerStyle);
        if (width > 0) l->setFixedWidth(width);
        return l;
    };
    // Spacer aligns with the row's left accent + dot column (3 + 16 + 10 ≈ 30 px).
    auto* dotSpacer = new QFrame();
    dotSpacer->setFixedWidth(13);    // matches row's content margin + dot
    headerLayout->addWidget(dotSpacer);
    headerLayout->addWidget(buildHeader("THREAT", 0), 4);
    headerLayout->addWidget(buildHeader("SEVERITY", 86), 0, Qt::AlignVCenter);
    headerLayout->addWidget(buildHeader("CONFIDENCE", 120), 0, Qt::AlignVCenter);
    headerLayout->addWidget(buildHeader("SOURCE", 90), 0, Qt::AlignVCenter);
    headerLayout->addWidget(buildHeader("DETECTED", 120), 0, Qt::AlignVCenter);
    headerLayout->addWidget(buildHeader("STATUS", 82), 0, Qt::AlignVCenter);
    auto* chevronSpacer = new QFrame();
    chevronSpacer->setFixedWidth(20);
    headerLayout->addWidget(chevronSpacer);
    listLayout->addWidget(headerBar);

    // ── Rows scroll area ───────────────────────────────────────────────
    auto* rowsScroll = new QScrollArea(m_listCard);
    rowsScroll->setWidgetResizable(true);
    rowsScroll->setFrameShape(QFrame::NoFrame);
    rowsScroll->setStyleSheet("background: transparent;");
    auto* rowsHost = new QWidget();
    rowsHost->setStyleSheet("background: transparent;");
    m_rowsLayout = new QVBoxLayout(rowsHost);
    m_rowsLayout->setContentsMargins(0, 14, 0, 14);
    // Generous spacing between cards — this is the "stacked" feel.
    m_rowsLayout->setSpacing(10);
    m_rowsLayout->addStretch(1);   // pushes rows to the top
    rowsScroll->setWidget(rowsHost);
    listLayout->addWidget(rowsScroll, 1);

    m_emptyState = new QLabel(
        "No findings yet. Run a scan from the Dashboard.", m_listCard);
    m_emptyState->setAlignment(Qt::AlignCenter);
    m_emptyState->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent; padding: 60px 40px; }")
            .arg(Theme::Color::textMuted)
            .arg(Theme::Type::qss(Theme::Type::Body)));
    listLayout->addWidget(m_emptyState);

    m_resultsCount = new QLabel("0 results", m_listCard);
    m_resultsCount->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent;"
        " padding: 14px 4px 0 4px; }")
            .arg(Theme::Color::textMuted)
            .arg(Theme::Type::qss(Theme::Type::Caption)));
    listLayout->addWidget(m_resultsCount);

    split->addWidget(m_listCard, 5);

    // Right: detail panel
    m_detailPanel = new QFrame(content);
    m_detailPanel->setObjectName("OdyDetailPanel");
    m_detailPanel->setAttribute(Qt::WA_StyledBackground, true);
    m_detailPanel->setMinimumWidth(400);
    m_detailPanel->setMaximumWidth(440);
    m_detailPanel->setStyleSheet(QString(
        "QFrame#OdyDetailPanel {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: 12px;"
        "}"
    ).arg(Theme::Color::bgCard, Theme::Color::borderSubtle));

    auto* dp = new QVBoxLayout(m_detailPanel);
    dp->setContentsMargins(20, 18, 20, 18);
    dp->setSpacing(16);

    // ── Detail empty state ─────────────────────────────────────────────
    m_detailEmpty = new QLabel(
        "Select a threat to see details.", m_detailPanel);
    m_detailEmpty->setAlignment(Qt::AlignCenter);
    m_detailEmpty->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent; padding: 60px 20px; }")
            .arg(Theme::Color::textMuted)
            .arg(Theme::Type::qss(Theme::Type::Body)));
    dp->addWidget(m_detailEmpty);

    // ── Detail header (title + severity + confidence bar) ─────────────
    auto* dpHeader = new QVBoxLayout();
    dpHeader->setSpacing(8);

    m_detailTitle = new QLabel("—", m_detailPanel);
    m_detailTitle->setWordWrap(true);
    m_detailTitle->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent; }")
            .arg(Theme::Color::textPrimary)
            .arg(Theme::Type::qss(Theme::Type::H1, Theme::Type::WeightBold)));
    dpHeader->addWidget(m_detailTitle);

    auto* sevRow = new QHBoxLayout();
    sevRow->setSpacing(10);
    m_detailSeverity = new QLabel("—", m_detailPanel);
    m_detailSeverity->setAlignment(Qt::AlignCenter);
    m_detailSeverity->setMinimumWidth(76);
    m_detailSeverity->setStyleSheet(QString(
        "QLabel { color: white; background-color: %1;"
        " border-radius: 6px; padding: 4px 10px; %2 }")
            .arg(Theme::Color::severityCritical)
            .arg(Theme::Type::qss(Theme::Type::Caption,
                                    Theme::Type::WeightBold)));
    sevRow->addWidget(m_detailSeverity, 0, Qt::AlignVCenter);

    m_detailConfText = new QLabel("Confidence: —", m_detailPanel);
    m_detailConfText->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent; }")
            .arg(Theme::Color::textSecondary)
            .arg(Theme::Type::qss(Theme::Type::Small)));
    sevRow->addWidget(m_detailConfText, 0, Qt::AlignVCenter);

    m_detailConfBar = new QProgressBar(m_detailPanel);
    m_detailConfBar->setRange(0, 1000);
    m_detailConfBar->setTextVisible(false);
    m_detailConfBar->setFixedHeight(4);
    m_detailConfBar->setStyleSheet(QString(
        "QProgressBar { background-color: %1; border-radius: 2px; }"
        "QProgressBar::chunk { background-color: %2; border-radius: 2px; }"
    ).arg(Theme::Color::borderSubtle, Theme::Color::severityCritical));
    sevRow->addWidget(m_detailConfBar, 1);

    dpHeader->addLayout(sevRow);
    dp->addLayout(dpHeader);

    // ── File info table ────────────────────────────────────────────────
    auto* fileInfo = new QFrame(m_detailPanel);
    fileInfo->setStyleSheet("background: transparent;");
    auto* fi = new QVBoxLayout(fileInfo);
    fi->setContentsMargins(0, 0, 0, 0);
    fi->setSpacing(6);

    auto buildKV = [this, fi](const QString& key, QLabel*& valOut,
                                bool monospace = false) {
        auto* row = new QHBoxLayout();
        row->setSpacing(12);
        auto* k = new QLabel(key);
        k->setFixedWidth(82);
        k->setStyleSheet(QString(
            "QLabel { color: %1; %2 background: transparent; }")
                .arg(Theme::Color::textSecondary)
                .arg(Theme::Type::qss(Theme::Type::Small)));
        row->addWidget(k);

        valOut = new QLabel("—");
        valOut->setWordWrap(true);
        valOut->setTextInteractionFlags(Qt::TextSelectableByMouse);
        const QString vqss = monospace
            ? QString("QLabel { color: %1; %2 background: transparent;"
                        " font-family: monospace; }")
                  .arg(Theme::Color::textPrimary)
                  .arg(Theme::Type::qss(Theme::Type::Small))
            : QString("QLabel { color: %1; %2 background: transparent; }")
                  .arg(Theme::Color::textPrimary)
                  .arg(Theme::Type::qss(Theme::Type::Body));
        valOut->setStyleSheet(vqss);
        row->addWidget(valOut, 1);
        fi->addLayout(row);
    };

    buildKV("Source",    m_detailSource);
    buildKV("Detected",  m_detailDetected);
    buildKV("File Path", m_detailFilePath);
    buildKV("File Size", m_detailFileSize);
    buildKV("SHA-256",   m_detailSha256, /*monospace=*/true);

    dp->addWidget(fileInfo);

    // ── DetailSection bullets ──────────────────────────────────────────
    m_secWhyFlagged = new DetailSection("Why was this flagged?",
                                          Theme::Color::severityCritical,
                                          m_detailPanel);
    dp->addWidget(m_secWhyFlagged);

    m_secAiSummary  = new DetailSection("AI Summary",
                                          Theme::Color::accentBlue,
                                          m_detailPanel);
    dp->addWidget(m_secAiSummary);

    m_secIndicators = new DetailSection("Indicators",
                                          Theme::Color::severityMedium,
                                          m_detailPanel);
    dp->addWidget(m_secIndicators);

    m_secActions    = new DetailSection("Recommended Actions",
                                          Theme::Color::severitySafe,
                                          m_detailPanel);
    dp->addWidget(m_secActions);

    dp->addStretch(1);

    // ── Action buttons row ─────────────────────────────────────────────
    auto* actions = new QHBoxLayout();
    actions->setSpacing(10);

    m_btnQuarantine = new QPushButton("Quarantine", m_detailPanel);
    m_btnQuarantine->setCursor(Qt::PointingHandCursor);
    // Phase 5 — wired to ResponseManager. Button stays disabled until a
    // finding is selected (populateDetail() enables it for File targets).
    m_btnQuarantine->setEnabled(false);
    m_btnQuarantine->setToolTip("Move file to quarantine (reversible)");
    m_btnQuarantine->setStyleSheet(QString(
        "QPushButton { background-color: %1; color: white; border: none;"
        " border-radius: 8px; padding: 10px 18px; %2 }"
        "QPushButton:hover { background-color: %3; }"
        "QPushButton:disabled { background-color: %4; color: %5; }"
    )
    .arg(Theme::Color::accentBlue)
    .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi))
    .arg(Theme::Color::accentBlueHover)
    .arg(Theme::Color::bgSecondary)
    .arg(Theme::Color::textMuted));
    connect(m_btnQuarantine, &QPushButton::clicked,
            this,            &ResultsPage::onQuarantineClicked);
    actions->addWidget(m_btnQuarantine, 1);

    auto styleSecondaryBtn = [](QPushButton* b) {
        b->setCursor(Qt::PointingHandCursor);
        b->setEnabled(false);
        b->setToolTip("Coming soon");
        b->setStyleSheet(QString(
            "QPushButton { background: transparent; color: %1;"
            " border: 1px solid %2; border-radius: 8px;"
            " padding: 10px 18px; %3 }"
            "QPushButton:hover { color: white; background-color: %4; }"
            "QPushButton:disabled { color: %5; }"
        )
        .arg(Theme::Color::textPrimary, Theme::Color::borderSubtle)
        .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi))
        .arg(Theme::Color::severityCritical)
        .arg(Theme::Color::textMuted));
    };

    // Delete is intentionally NOT wired — Phase 5 forbids destructive,
    // non-reversible actions. Quarantine is the reversible substitute.
    m_btnDelete = new QPushButton("Delete", m_detailPanel);
    styleSecondaryBtn(m_btnDelete);
    m_btnDelete->setToolTip(
        "Disabled by design — use Quarantine (reversible) instead.");
    actions->addWidget(m_btnDelete, 1);

    // Ignore = "Add to Allowlist" — wired to ResponseManager so the next
    // scan suppresses this finding. Hash-based when SHA-256 is available,
    // path-based otherwise.
    m_btnIgnore = new QPushButton("Ignore", m_detailPanel);
    styleSecondaryBtn(m_btnIgnore);
    m_btnIgnore->setEnabled(false);
    m_btnIgnore->setToolTip(
        "Add this file to the allowlist (suppress future findings)");
    connect(m_btnIgnore, &QPushButton::clicked,
            this,        &ResultsPage::onIgnoreClicked);
    actions->addWidget(m_btnIgnore, 1);

    dp->addLayout(actions);

    split->addWidget(m_detailPanel, 0);
    main->addLayout(split, 1);

    scroll->setWidget(content);

    // Hide detail content until a row is clicked (only show empty state).
    m_detailTitle->parentWidget()->setVisible(true);   // keep parents alive
    m_detailEmpty->setVisible(true);
    auto setSiblingsVisible = [&](bool v) {
        m_detailTitle->setVisible(v);
        m_detailSeverity->setVisible(v);
        m_detailConfText->setVisible(v);
        m_detailConfBar->setVisible(v);
        m_secWhyFlagged->setVisible(v);
        m_secAiSummary->setVisible(v);
        m_secIndicators->setVisible(v);
        m_secActions->setVisible(v);
        if (m_btnQuarantine) m_btnQuarantine->setVisible(v);
        if (m_btnDelete)      m_btnDelete->setVisible(v);
        if (m_btnIgnore)      m_btnIgnore->setVisible(v);
        // File-info kv labels share parent — toggle parent
        if (m_detailSource) m_detailSource->parentWidget()->setVisible(v);
    };
    setSiblingsVisible(false);
}

// ============================================================================
//  Public API
// ============================================================================
void ResultsPage::setFindings(const QVector<SuspiciousFile>& findings)
{
    m_findings = findings;
    m_selectedIndex = -1;
    rebuildVisibleRows();
    recomputeStats();
}

void ResultsPage::appendFinding(const SuspiciousFile& sf)
{
    m_findings.append(sf);
    rebuildVisibleRows();
    recomputeStats();
}

void ResultsPage::clear()
{
    m_findings.clear();
    m_selectedIndex = -1;
    rebuildVisibleRows();
    recomputeStats();
}

// ============================================================================
//  Filtering + rebuild
// ============================================================================
bool ResultsPage::rowMatchesFilter(const SuspiciousFile& sf) const
{
    // Search
    const QString q = m_searchInput ? m_searchInput->text().trimmed().toLower()
                                     : QString();
    if (!q.isEmpty()) {
        const bool hit = sf.fileName.toLower().contains(q)
                       || sf.filePath.toLower().contains(q)
                       || sf.cveId.toLower().contains(q)
                       || sf.category.toLower().contains(q)
                       || sf.classificationLevel.toLower().contains(q);
        if (!hit) return false;
    }

    // Severity filter
    const QString sevSel = m_severityFilter
                              ? m_severityFilter->currentText() : "All Severities";
    if (sevSel != "All Severities") {
        const QString rowSev = severityFromFinding(sf);
        const QString want   = sevSel.toLower().replace(' ', '-');   // "Needs Review" → "needs-review"
        if (rowSev != want) return false;
    }

    // Source filter
    const QString srcSel = m_sourceFilter
                              ? m_sourceFilter->currentText() : "All Sources";
    if (srcSel != "All Sources") {
        if (sourceForFinding(sf) != srcSel) return false;
    }
    return true;
}

void ResultsPage::rebuildVisibleRows()
{
    // Drop existing row widgets (keep the trailing stretch).
    for (ThreatRow* r : m_rows) r->deleteLater();
    m_rows.clear();

    int kept = 0;
    for (int i = 0; i < m_findings.size(); ++i) {
        const SuspiciousFile& sf = m_findings[i];
        if (!rowMatchesFilter(sf)) continue;

        auto* row = new ThreatRow();
        row->setPayload(i);
        row->setThreatName(!sf.cveId.isEmpty() ? sf.cveId : sf.fileName);
        QString subtext = sf.filePath;
        if (subtext.length() > 70)
            subtext = "…" + subtext.right(69);
        row->setSubtext(subtext);
        row->setSeverity(severityFromFinding(sf));
        row->setConfidence(sf.anomalyScore > 0
                              ? sf.anomalyScore
                              : sf.confidencePct / 100.0f);
        row->setSource(sourceForFinding(sf));
        row->setDetected(sf.lastModified.isValid()
                            ? sf.lastModified.toString("MMM d, yyyy")
                            : "—");
        row->setStatus("Detected");
        row->setSelected(i == m_selectedIndex);
        connect(row, &ThreatRow::clicked,
                this, &ResultsPage::onRowClicked);
        m_rowsLayout->insertWidget(m_rowsLayout->count() - 1, row);
        m_rows.append(row);
        ++kept;
    }

    if (m_emptyState)
        m_emptyState->setVisible(kept == 0);
    if (m_resultsCount)
        m_resultsCount->setText(QString("Showing %1 of %2 results")
                                  .arg(kept).arg(m_findings.size()));
}

void ResultsPage::recomputeStats()
{
    int critical = 0, suspicious = 0, needsReview = 0;
    double sumScore = 0.0;
    int    sumCount = 0;
    for (const SuspiciousFile& sf : m_findings) {
        const QString sev = severityFromFinding(sf);
        if      (sev == "critical")     ++critical;
        else if (sev == "suspicious")   ++suspicious;
        else if (sev == "needs-review") ++needsReview;
        if (sf.anomalyScore > 0) {
            sumScore += sf.anomalyScore;
            ++sumCount;
        }
    }

    m_kpiFilesScanned->setValue(QString("%L1").arg(m_findings.size()));
    m_kpiFilesScanned->setSubtitle(m_findings.isEmpty()
                                      ? "No findings yet"
                                      : "Total findings analyzed");

    m_kpiSuspicious->setValue(QString::number(critical + suspicious));
    m_kpiSuspicious->setSubtitle(critical + suspicious > 0
                                   ? "Require attention"
                                   : "All clear");

    m_kpiNeedsReview->setValue(QString::number(needsReview));
    m_kpiNeedsReview->setSubtitle("Manual review");

    const double avg = sumCount > 0 ? sumScore / sumCount : 0.0;
    m_kpiAvgScore->setValue(QString("%1 / 1.00").arg(avg, 0, 'f', 2));
    m_kpiAvgScore->setSubtitle("Average across all");
}

// ============================================================================
//  Slots
// ============================================================================
void ResultsPage::onSearchChanged()
{
    rebuildVisibleRows();
}

void ResultsPage::onFilterChanged()
{
    rebuildVisibleRows();
}

void ResultsPage::onRowClicked(int findingIndex)
{
    if (findingIndex < 0 || findingIndex >= m_findings.size()) return;
    m_selectedIndex = findingIndex;

    for (ThreatRow* r : m_rows)
        r->setSelected(r->payload() == findingIndex);

    populateDetail(m_findings[findingIndex]);
}

// ============================================================================
//  Detail population
// ============================================================================
void ResultsPage::populateDetail(const SuspiciousFile& sf)
{
    // Show detail content; hide empty-state placeholder.
    m_detailEmpty->setVisible(false);

    auto setVis = [](QWidget* w, bool v) { if (w) w->setVisible(v); };
    setVis(m_detailTitle,    true);
    setVis(m_detailSeverity, true);
    setVis(m_detailConfText, true);
    setVis(m_detailConfBar,  true);
    setVis(m_secWhyFlagged,  true);
    setVis(m_secAiSummary,   true);
    setVis(m_secIndicators,  true);
    setVis(m_secActions,     true);
    setVis(m_btnQuarantine,  true);
    setVis(m_btnDelete,      true);
    setVis(m_btnIgnore,      true);
    if (m_detailSource) setVis(m_detailSource->parentWidget(), true);

    // Phase 5 — enable wired action buttons now that we have a finding.
    // The file path is the gating requirement (Quarantine + Allowlist need it).
    const bool havePath = !sf.filePath.isEmpty();
    if (m_btnQuarantine) m_btnQuarantine->setEnabled(havePath);
    if (m_btnIgnore)     m_btnIgnore->setEnabled(havePath);
    // Delete intentionally remains disabled — see button-construction comment.

    // Title
    m_detailTitle->setText(!sf.cveId.isEmpty() ? sf.cveId : sf.fileName);

    // Severity badge
    const QString sev    = severityFromFinding(sf);
    const QString sevHex =
        (sev == "critical")          ? Theme::Color::severityCritical :
        (sev == "clean")              ? Theme::Color::severitySafe     :
                                        Theme::Color::severityMedium;
    QString sevText =
        (sev == "critical")     ? "Critical" :
        (sev == "suspicious")   ? "Suspicious" :
        (sev == "needs-review") ? "Needs Review" :
        (sev == "clean")          ? "Clean" : "Unknown";
    m_detailSeverity->setText(sevText);
    m_detailSeverity->setStyleSheet(QString(
        "QLabel { color: white; background-color: %1;"
        " border-radius: 6px; padding: 4px 10px; %2 }")
            .arg(sevHex)
            .arg(Theme::Type::qss(Theme::Type::Caption,
                                    Theme::Type::WeightBold)));

    // Confidence
    const float pct = sf.anomalyScore > 0 ? sf.anomalyScore
                                            : sf.confidencePct / 100.0f;
    m_detailConfText->setText(QString("Confidence: %1")
                                .arg(pct, 0, 'f', 3));
    m_detailConfBar->setValue(static_cast<int>(qBound(0.0f, pct, 1.0f) * 1000));
    m_detailConfBar->setStyleSheet(QString(
        "QProgressBar { background-color: %1; border-radius: 2px; }"
        "QProgressBar::chunk { background-color: %2; border-radius: 2px; }"
    ).arg(Theme::Color::borderSubtle, sevHex));

    // File info
    m_detailSource->setText(sourceForFinding(sf));
    m_detailDetected->setText(sf.lastModified.isValid()
        ? sf.lastModified.toString("MMM d, yyyy hh:mm:ss")
        : "—");
    m_detailFilePath->setText(sf.filePath.isEmpty() ? "—" : sf.filePath);
    m_detailFileSize->setText(sf.sizeBytes > 0 ? prettyBytes(sf.sizeBytes) : "—");
    m_detailSha256->setText(sf.sha256.isEmpty() ? "—" : abbrevHash(sf.sha256));
    m_detailSha256->setToolTip(sf.sha256);

    // ── Polish.Cards — hide empty sections entirely ────────────────────
    // No "(none)" placeholders; an empty bucket means the section
    // isn't rendered at all, removing visual noise from the panel.

    // Why flagged: top-4 indicators or fallback to reason
    QStringList whyBullets;
    if (!sf.keyIndicators.isEmpty()) {
        for (int i = 0; i < qMin(4, int(sf.keyIndicators.size())); ++i)
            whyBullets.append(sf.keyIndicators[i]);
    } else if (!sf.reason.isEmpty()) {
        // Reason can be a multi-line string with bullets baked in by the
        // scanner — split into separate bullets when newlines are present.
        for (const QString& line : sf.reason.split('\n', Qt::SkipEmptyParts)) {
            const QString tr = line.trimmed();
            if (!tr.isEmpty()) whyBullets.append(tr);
        }
    }
    if (whyBullets.isEmpty()) {
        m_secWhyFlagged->setVisible(false);
    } else {
        m_secWhyFlagged->setVisible(true);
        m_secWhyFlagged->setBullets(whyBullets);
    }

    // AI Summary — short bullet list when sentences split cleanly,
    // otherwise a single short paragraph. Hidden when empty.
    if (sf.aiSummary.isEmpty()) {
        m_secAiSummary->setVisible(false);
    } else {
        m_secAiSummary->setVisible(true);
        // Try splitting on ". " to get 2-3 bullets max; fall back to body.
        QStringList sentences = sf.aiSummary.split(
            QRegularExpression("(?<=[.!?])\\s+"),
            Qt::SkipEmptyParts);
        // Clean leading/trailing whitespace and drop empties.
        QStringList cleaned;
        for (QString s : sentences) {
            s = s.trimmed();
            if (!s.isEmpty()) cleaned.append(s);
        }
        if (cleaned.size() >= 2 && cleaned.size() <= 4) {
            m_secAiSummary->setBullets(cleaned);
        } else {
            m_secAiSummary->setBody(sf.aiSummary);
        }
    }

    // Indicators — only render if there's actual content beyond what
    // already showed up under "Why was this flagged?".
    QStringList indicatorList;
    for (int i = 4; i < sf.keyIndicators.size(); ++i)
        indicatorList.append(sf.keyIndicators[i]);
    if (indicatorList.isEmpty()) {
        m_secIndicators->setVisible(false);
    } else {
        m_secIndicators->setVisible(true);
        m_secIndicators->setBullets(indicatorList);
    }

    // Recommended actions — hide if empty.
    if (sf.recommendedActions.isEmpty()) {
        m_secActions->setVisible(false);
    } else {
        m_secActions->setVisible(true);
        m_secActions->setBullets(sf.recommendedActions);
    }
}

// ============================================================================
//  Phase 5 — Response & Control Layer slots
// ============================================================================
void ResultsPage::onQuarantineClicked()
{
    if (m_selectedIndex < 0 || m_selectedIndex >= m_findings.size())
        return;
    const SuspiciousFile& sf = m_findings[m_selectedIndex];
    if (sf.filePath.isEmpty()) {
        QMessageBox::warning(this, "Quarantine",
            "No file path available for this finding.");
        return;
    }

    // Confirmation dialog — required for destructive/sensitive actions.
    // The ResponseManager will reject the request without userConfirmed=true,
    // so this dialog is the contract that lets the call succeed.
    QMessageBox box(this);
    box.setIcon(QMessageBox::Warning);
    box.setWindowTitle("Quarantine file");
    box.setText(QString("Move this file to quarantine?"));
    box.setInformativeText(QString(
        "<b>%1</b><br><br>"
        "<i>%2</i><br><br>"
        "The file will be moved (not deleted) to the Odysseus quarantine "
        "directory with read-only permissions. You can restore it later "
        "from the quarantine page. This action will be recorded in the "
        "action log.")
            .arg(sf.fileName.toHtmlEscaped(),
                 sf.filePath.toHtmlEscaped()));
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
    box.setDefaultButton(QMessageBox::Cancel);
    if (box.exec() != QMessageBox::Yes)
        return;

    // Build the request.
    namespace R = odysseus::response;
    R::ActionRequest req;
    req.action               = R::ActionType::QuarantineFile;
    req.userConfirmed        = true;          // dialog above is the consent
    req.target.kind          = R::TargetKind::File;
    req.target.path          = sf.filePath.toStdString();
    req.target.sha256        = sf.sha256.toStdString();
    req.target.label         = sf.fileName.toStdString();
    req.target.sourceId      = sf.filePath.toStdString();   // stable per file
    req.reason               = sf.reason.isEmpty()
                                   ? std::string("User-initiated quarantine "
                                                  "from Results page")
                                   : sf.reason.toStdString();

    R::ActionResult res = R::globalResponseManager().execute(req);

    if (res.success) {
        QMessageBox::information(this, "Quarantine",
            QString("File quarantined successfully.\n\nMoved to:\n%1")
                .arg(QString::fromStdString(res.newPath)));
        // Disable the buttons so the user can't double-quarantine.
        if (m_btnQuarantine) m_btnQuarantine->setEnabled(false);
        if (m_btnIgnore)     m_btnIgnore->setEnabled(false);
        // Mark the row as resolved in the visible list. The simplest
        // way without restructuring is to update the local copy's reason
        // and request a row rebuild on next selection.
        m_findings[m_selectedIndex].reason =
            QString("[QUARANTINED] ") + m_findings[m_selectedIndex].reason;
    } else {
        QMessageBox::critical(this, "Quarantine failed",
            QString("Could not quarantine file.\n\n%1")
                .arg(QString::fromStdString(
                    res.errorMessage.empty() ? res.message
                                              : res.errorMessage)));
    }
}

void ResultsPage::onIgnoreClicked()
{
    if (m_selectedIndex < 0 || m_selectedIndex >= m_findings.size())
        return;
    const SuspiciousFile& sf = m_findings[m_selectedIndex];
    if (sf.filePath.isEmpty()) {
        QMessageBox::warning(this, "Ignore",
            "No file path available for this finding.");
        return;
    }

    // Confirmation — adding to the allowlist suppresses future findings
    // for this file. We prefer SHA-256 entries when available.
    const QString idLine = sf.sha256.isEmpty()
        ? QString("Path: %1").arg(sf.filePath.toHtmlEscaped())
        : QString("SHA-256: %1").arg(sf.sha256);
    QMessageBox box(this);
    box.setIcon(QMessageBox::Question);
    box.setWindowTitle("Add to allowlist");
    box.setText(QString("Suppress future findings for this file?"));
    box.setInformativeText(QString(
        "<b>%1</b><br><br>"
        "%2<br><br>"
        "Subsequent scans will not flag this file. You can remove the "
        "entry later from the Settings page.")
            .arg(sf.fileName.toHtmlEscaped(), idLine));
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
    box.setDefaultButton(QMessageBox::Cancel);
    if (box.exec() != QMessageBox::Yes)
        return;

    namespace R = odysseus::response;
    R::ActionRequest req;
    req.action          = R::ActionType::AddToAllowlist;
    req.userConfirmed   = true;          // not strictly required for allowlist,
                                          // but consistent and audited.
    req.target.kind     = R::TargetKind::File;
    req.target.path     = sf.filePath.toStdString();
    req.target.sha256   = sf.sha256.toStdString();   // ResponseManager
                                                       // prefers SHA-256
    req.target.label    = sf.fileName.toStdString();
    req.reason          = std::string("User-initiated ignore from Results page");

    R::ActionResult res = R::globalResponseManager().execute(req);

    if (res.success) {
        QMessageBox::information(this, "Allowlisted",
            QString("Added to allowlist.\n\n%1\n\n"
                    "This file will not appear in future scan results.")
                .arg(QString::fromStdString(res.message)));
        if (m_btnIgnore) m_btnIgnore->setEnabled(false);
    } else {
        QMessageBox::critical(this, "Allowlist failed",
            QString("Could not add to allowlist.\n\n%1")
                .arg(QString::fromStdString(
                    res.errorMessage.empty() ? res.message
                                              : res.errorMessage)));
    }
}
