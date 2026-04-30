// ============================================================================
// AlertDetailPanel.cpp
// ============================================================================

#include "AlertDetailPanel.h"
#include "SeverityBadge.h"
#include "../theme/DashboardTheme.h"

// Phase 5 — Response & Control Layer
#include "response/ResponseManagerSingleton.h"
#include "response/ResponseManager.h"
#include "response/ResponseTypes.h"

#include <QLabel>
#include <QPushButton>
#include <QTabWidget>
#include <QPlainTextEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGuiApplication>
#include <QClipboard>
#include <QDesktopServices>
#include <QUrl>
#include <QFileInfo>
#include <QDateTime>
#include <QMessageBox>

namespace {

QString abbrevHash(const QString& hex, int head = 12, int tail = 8)
{
    if (hex.length() <= head + tail + 3) return hex;
    return hex.left(head) + "…" + hex.right(tail);
}

}  // anonymous

AlertDetailPanel::AlertDetailPanel(QWidget* parent)
    : QFrame(parent)
{
    setObjectName("OdyAlertDetailPanel");
    setAttribute(Qt::WA_StyledBackground, true);
    setMinimumWidth(380);
    setMaximumWidth(460);
    setStyleSheet(QString(
        "QFrame#OdyAlertDetailPanel {"
        "  background-color: %1; border: 1px solid %2; border-radius: 12px;"
        "}"
    ).arg(Theme::Color::bgCard, Theme::Color::borderSubtle));
    buildUi();
    clear();
}

// ============================================================================
//  Layout
// ============================================================================
void AlertDetailPanel::buildUi()
{
    auto* main = new QVBoxLayout(this);
    main->setContentsMargins(20, 18, 20, 18);
    main->setSpacing(14);

    // Empty-state placeholder
    m_emptyState = new QLabel("Select an alert to see details.", this);
    m_emptyState->setAlignment(Qt::AlignCenter);
    m_emptyState->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent; padding: 60px 20px; }")
            .arg(Theme::Color::textMuted)
            .arg(Theme::Type::qss(Theme::Type::Body)));
    main->addWidget(m_emptyState);

    // ── Header ─────────────────────────────────────────────────────────
    auto* topRow = new QHBoxLayout();
    topRow->setSpacing(8);
    m_severity = new SeverityBadge(EDR::Severity::Info,
                                     SeverityBadge::Filled, this);
    topRow->addWidget(m_severity, 0, Qt::AlignTop);

    m_statusBadge = new QLabel("Active", this);
    m_statusBadge->setAlignment(Qt::AlignCenter);
    m_statusBadge->setMinimumWidth(64);
    // Default style is "Active" green-ish — refreshed in setAlert().
    m_statusBadge->setStyleSheet(QString(
        "QLabel { color: %1; background: transparent;"
        " border: 1px solid %1; border-radius: 6px;"
        " padding: 3px 10px; %2 }")
            .arg(Theme::Color::severitySafe)
            .arg(Theme::Type::qss(Theme::Type::Caption,
                                    Theme::Type::WeightSemi)));
    topRow->addWidget(m_statusBadge, 0, Qt::AlignTop);

    topRow->addStretch(1);
    m_timestampLab = new QLabel("—", this);
    m_timestampLab->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent; }")
            .arg(Theme::Color::textMuted)
            .arg(Theme::Type::qss(Theme::Type::Caption)));
    topRow->addWidget(m_timestampLab, 0, Qt::AlignTop);
    main->addLayout(topRow);

    m_titleLab = new QLabel("—", this);
    m_titleLab->setWordWrap(true);
    m_titleLab->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent; }")
            .arg(Theme::Color::textPrimary)
            .arg(Theme::Type::qss(Theme::Type::H1, Theme::Type::WeightBold)));
    main->addWidget(m_titleLab);

    m_categoryLab = new QLabel("", this);
    m_categoryLab->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent;"
        " text-transform: uppercase; letter-spacing: 0.5px; }")
            .arg(Theme::Color::textSecondary)
            .arg(Theme::Type::qss(Theme::Type::Caption,
                                    Theme::Type::WeightSemi)));
    main->addWidget(m_categoryLab);

    m_groupBanner = new QLabel("", this);
    m_groupBanner->setWordWrap(true);
    m_groupBanner->setStyleSheet(QString(
        "QLabel { color: %1; background-color: %2;"
        " border: 1px solid %1; border-radius: 6px;"
        " padding: 6px 10px; %3 }")
            .arg(Theme::Color::accentBlue,
                 Theme::Color::bgSecondary)
            .arg(Theme::Type::qss(Theme::Type::Caption,
                                    Theme::Type::WeightSemi)));
    m_groupBanner->setVisible(false);
    main->addWidget(m_groupBanner);

    // ── Tabs ───────────────────────────────────────────────────────────
    m_tabs = new QTabWidget(this);
    m_tabs->setStyleSheet(QString(
        "QTabWidget::pane { border: none; background: transparent;"
        " padding-top: 8px; }"
        "QTabBar::tab {"
        "  background: transparent; color: %1;"
        "  padding: 6px 12px; margin-right: 4px;"
        "  border-bottom: 2px solid transparent;"
        "  %2"
        "}"
        "QTabBar::tab:hover { color: %3; }"
        "QTabBar::tab:selected {"
        "  color: %3; border-bottom: 2px solid %4;"
        "}"
    ).arg(Theme::Color::textSecondary)
     .arg(Theme::Type::qss(Theme::Type::Caption, Theme::Type::WeightSemi))
     .arg(Theme::Color::textPrimary)
     .arg(Theme::Color::accentBlue));

    auto sectionTitleStyle = QString(
        "QLabel { color: %1; %2 background: transparent;"
        " padding-top: 4px; }")
            .arg(Theme::Color::textSecondary)
            .arg(Theme::Type::qss(Theme::Type::Caption,
                                    Theme::Type::WeightSemi));
    auto bodyStyle = QString(
        "QLabel { color: %1; %2 background: transparent;"
        " line-height: 1.45; }")
            .arg(Theme::Color::textPrimary)
            .arg(Theme::Type::qss(Theme::Type::Body));

    auto buildKv = [&](QVBoxLayout* host, const QString& key, QLabel*& valOut,
                        bool monospace = false) {
        auto* row = new QHBoxLayout();
        row->setSpacing(10);
        auto* k = new QLabel(key);
        k->setFixedWidth(100);
        k->setStyleSheet(QString(
            "QLabel { color: %1; %2 background: transparent; }")
                .arg(Theme::Color::textSecondary)
                .arg(Theme::Type::qss(Theme::Type::Caption)));
        row->addWidget(k);
        valOut = new QLabel("—");
        valOut->setWordWrap(true);
        valOut->setTextInteractionFlags(Qt::TextSelectableByMouse);
        valOut->setStyleSheet(monospace
            ? QString("QLabel { color: %1; %2 background: transparent;"
                        " font-family: monospace; }")
                  .arg(Theme::Color::textPrimary)
                  .arg(Theme::Type::qss(Theme::Type::Small))
            : QString("QLabel { color: %1; %2 background: transparent; }")
                  .arg(Theme::Color::textPrimary)
                  .arg(Theme::Type::qss(Theme::Type::Body)));
        row->addWidget(valOut, 1);
        host->addLayout(row);
    };

    // ── Tab 1: Overview ────────────────────────────────────────────────
    {
        auto* w = new QWidget();
        w->setStyleSheet("background: transparent;");
        auto* v = new QVBoxLayout(w);
        v->setContentsMargins(0, 8, 0, 0);
        v->setSpacing(10);

        auto* sumTitle = new QLabel("Summary", w);
        sumTitle->setStyleSheet(sectionTitleStyle);
        v->addWidget(sumTitle);

        m_overSummary = new QLabel("—", w);
        m_overSummary->setWordWrap(true);
        m_overSummary->setTextInteractionFlags(Qt::TextSelectableByMouse);
        m_overSummary->setStyleSheet(bodyStyle);
        v->addWidget(m_overSummary);

        auto* factsTitle = new QLabel("Key facts", w);
        factsTitle->setStyleSheet(sectionTitleStyle);
        v->addWidget(factsTitle);

        buildKv(v, "First seen",  m_overFirstSeen);
        buildKv(v, "Last seen",   m_overLastSeen);
        buildKv(v, "Source",      m_overSource);
        buildKv(v, "Process",     m_overProcess);

        v->addStretch(1);
        m_tabs->addTab(w, "Overview");
    }

    // ── Tab 2: Why Flagged ─────────────────────────────────────────────
    {
        auto* w = new QWidget();
        w->setStyleSheet("background: transparent;");
        auto* v = new QVBoxLayout(w);
        v->setContentsMargins(0, 8, 0, 0);
        v->setSpacing(8);

        m_whyEmpty = new QLabel("(no specific indicators captured)", w);
        m_whyEmpty->setStyleSheet(QString(
            "QLabel { color: %1; %2 background: transparent;"
            " font-style: italic; }")
                .arg(Theme::Color::textMuted)
                .arg(Theme::Type::qss(Theme::Type::Body)));
        v->addWidget(m_whyEmpty);

        m_whyLayout = new QVBoxLayout();
        m_whyLayout->setContentsMargins(0, 0, 0, 0);
        m_whyLayout->setSpacing(4);
        v->addLayout(m_whyLayout);

        v->addStretch(1);
        m_tabs->addTab(w, "Why Flagged");
    }

    // ── Tab 3: Indicators ──────────────────────────────────────────────
    {
        auto* w = new QWidget();
        w->setStyleSheet("background: transparent;");
        auto* v = new QVBoxLayout(w);
        v->setContentsMargins(0, 8, 0, 0);
        v->setSpacing(10);

        m_indEmpty = new QLabel(
            "No technical indicators (signing / hash / reputation) captured "
            "for this alert.", w);
        m_indEmpty->setWordWrap(true);
        m_indEmpty->setStyleSheet(QString(
            "QLabel { color: %1; %2 background: transparent;"
            " font-style: italic; }")
                .arg(Theme::Color::textMuted)
                .arg(Theme::Type::qss(Theme::Type::Body)));
        v->addWidget(m_indEmpty);

        // Trust row
        auto* trustTitle = new QLabel("Trust", w);
        trustTitle->setStyleSheet(sectionTitleStyle);
        v->addWidget(trustTitle);
        m_indTrust = new QLabel("—", w);
        m_indTrust->setStyleSheet(bodyStyle);
        m_indTrust->setTextInteractionFlags(Qt::TextSelectableByMouse);
        v->addWidget(m_indTrust);

        // Hash row + copy button
        m_indHashLabel = new QLabel("SHA-256", w);
        m_indHashLabel->setStyleSheet(sectionTitleStyle);
        v->addWidget(m_indHashLabel);

        auto* hashRow = new QHBoxLayout();
        hashRow->setSpacing(8);
        m_indHashVal = new QLabel("—", w);
        m_indHashVal->setStyleSheet(QString(
            "QLabel { color: %1; %2 background: transparent;"
            " font-family: monospace; }")
                .arg(Theme::Color::textPrimary)
                .arg(Theme::Type::qss(Theme::Type::Small)));
        m_indHashVal->setTextInteractionFlags(Qt::TextSelectableByMouse);
        hashRow->addWidget(m_indHashVal, 1);

        m_indHashCopy = new QPushButton("Copy", w);
        m_indHashCopy->setCursor(Qt::PointingHandCursor);
        m_indHashCopy->setStyleSheet(QString(
            "QPushButton { background: transparent; color: %1;"
            " border: 1px solid %2; border-radius: 6px;"
            " padding: 4px 10px; %3 }"
            "QPushButton:hover { color: white; background-color: %4; }"
        ).arg(Theme::Color::textPrimary, Theme::Color::borderSubtle)
         .arg(Theme::Type::qss(Theme::Type::Caption, Theme::Type::WeightSemi))
         .arg(Theme::Color::accentBlueSoft));
        connect(m_indHashCopy, &QPushButton::clicked, this, [this]() {
            if (!m_currentAlert.sha256.isEmpty())
                QGuiApplication::clipboard()->setText(m_currentAlert.sha256);
        });
        hashRow->addWidget(m_indHashCopy);
        v->addLayout(hashRow);

        // Reputation row
        auto* repTitle = new QLabel("Reputation", w);
        repTitle->setStyleSheet(sectionTitleStyle);
        v->addWidget(repTitle);
        m_indReputation = new QLabel("—", w);
        m_indReputation->setStyleSheet(bodyStyle);
        m_indReputation->setTextInteractionFlags(Qt::TextSelectableByMouse);
        v->addWidget(m_indReputation);

        v->addStretch(1);
        m_tabs->addTab(w, "Indicators");
    }

    // ── Tab 4: Details ─────────────────────────────────────────────────
    {
        auto* w = new QWidget();
        w->setStyleSheet("background: transparent;");
        auto* v = new QVBoxLayout(w);
        v->setContentsMargins(0, 8, 0, 0);
        v->setSpacing(8);

        m_detRaw = new QPlainTextEdit(w);
        m_detRaw->setReadOnly(true);
        m_detRaw->setStyleSheet(QString(
            "QPlainTextEdit {"
            "  background-color: %1; color: %2;"
            "  border: 1px solid %3; border-radius: 6px;"
            "  padding: 10px; font-family: monospace; font-size: 11px;"
            "}"
        ).arg(Theme::Color::bgPrimary, Theme::Color::textPrimary,
              Theme::Color::borderSubtle));
        v->addWidget(m_detRaw, 1);

        m_tabs->addTab(w, "Details");
    }

    main->addWidget(m_tabs, 1);

    // ── Action buttons ────────────────────────────────────────────────
    auto* actions = new QHBoxLayout();
    actions->setSpacing(8);

    auto styleSecondary = [&](QPushButton* b) {
        b->setCursor(Qt::PointingHandCursor);
        b->setStyleSheet(QString(
            "QPushButton { background: transparent; color: %1;"
            " border: 1px solid %2; border-radius: 8px;"
            " padding: 8px 14px; %3 }"
            "QPushButton:hover { color: white; background-color: %4; }"
            "QPushButton:disabled { color: %5; }"
        ).arg(Theme::Color::textPrimary, Theme::Color::borderSubtle)
         .arg(Theme::Type::qss(Theme::Type::Caption,
                                 Theme::Type::WeightSemi))
         .arg(Theme::Color::accentBlueSoft)
         .arg(Theme::Color::textMuted));
    };

    // Investigate is reserved for the future Threat-Intel page (where the
    // user can drill into a finding). Kept disabled to avoid scope creep
    // before the presentation.
    m_btnInvestigate = new QPushButton("Investigate", this);
    m_btnInvestigate->setEnabled(false);
    m_btnInvestigate->setToolTip("Coming soon");
    styleSecondary(m_btnInvestigate);
    actions->addWidget(m_btnInvestigate);

    // Phase 5 — Ignore = Add to Allowlist. Always enabled; the kind of
    // allowlist entry depends on the alert's category (chosen at click time).
    m_btnIgnore = new QPushButton("Ignore", this);
    m_btnIgnore->setToolTip("Suppress future alerts for this item");
    styleSecondary(m_btnIgnore);
    connect(m_btnIgnore, &QPushButton::clicked,
            this, &AlertDetailPanel::onIgnoreClicked);
    actions->addWidget(m_btnIgnore);

    // Phase 5 — Quarantine. Visible only when the alert maps to a real
    // file path on disk (set in setAlert).
    m_btnQuarantine = new QPushButton("Quarantine", this);
    m_btnQuarantine->setToolTip("Move file to quarantine (reversible)");
    styleSecondary(m_btnQuarantine);
    m_btnQuarantine->setVisible(false);   // shown opportunistically
    connect(m_btnQuarantine, &QPushButton::clicked,
            this, &AlertDetailPanel::onQuarantineClicked);
    actions->addWidget(m_btnQuarantine);

    m_btnOpenLoc = new QPushButton("Open Location", this);
    styleSecondary(m_btnOpenLoc);
    connect(m_btnOpenLoc, &QPushButton::clicked,
            this, &AlertDetailPanel::onOpenLocationClicked);
    actions->addWidget(m_btnOpenLoc);

    m_btnCopy = new QPushButton("Copy Details", this);
    styleSecondary(m_btnCopy);
    connect(m_btnCopy, &QPushButton::clicked,
            this, &AlertDetailPanel::onCopyDetailsClicked);
    actions->addWidget(m_btnCopy);

    main->addLayout(actions);

    setSectionsVisible(false);
}

void AlertDetailPanel::setSectionsVisible(bool v)
{
    auto setVis = [v](QWidget* w) { if (w) w->setVisible(v); };
    setVis(m_severity); setVis(m_statusBadge);
    setVis(m_timestampLab); setVis(m_titleLab);
    setVis(m_categoryLab); setVis(m_tabs);
    setVis(m_btnInvestigate); setVis(m_btnIgnore);
    setVis(m_btnOpenLoc); setVis(m_btnCopy);
    // Quarantine visibility is decided per-alert in setAlert() when v=true,
    // so we only force-hide here when v=false.
    if (m_btnQuarantine && !v) m_btnQuarantine->setVisible(false);
    if (m_groupBanner) m_groupBanner->setVisible(false);
}

// ============================================================================
//  Public API
// ============================================================================
void AlertDetailPanel::clear()
{
    if (m_emptyState) m_emptyState->setVisible(true);
    setSectionsVisible(false);
    m_currentAlert = EDR::Alert{};
}

void AlertDetailPanel::setAlert(const EDR::Alert& alert, int groupCount)
{
    m_currentAlert = alert;
    if (m_emptyState) m_emptyState->setVisible(false);
    setSectionsVisible(true);

    // Phase 5 — Quarantine is gated on the alert mapping to a real file
    // path on disk. Process / persistence / integrity alerts that point
    // at an actual binary qualify; cross-view (PID-set diff) and bare
    // kernel-extension bundle IDs do not.
    if (m_btnQuarantine) {
        const QFileInfo fi(alert.sourcePath);
        const bool sourceIsFile = !alert.sourcePath.isEmpty()
                                   && fi.isAbsolute()
                                   && fi.exists()
                                   && fi.isFile();
        m_btnQuarantine->setVisible(sourceIsFile);
        m_btnQuarantine->setEnabled(sourceIsFile);
    }

    // Header
    m_severity->setSeverity(alert.severity);
    m_severity->setBadgeStyle(SeverityBadge::Filled);
    m_titleLab->setText(alert.title);
    m_categoryLab->setText(alert.category);
    m_timestampLab->setText(
        alert.lastSeen.isValid()
            ? alert.lastSeen.toString("MMM d, yyyy hh:mm:ss")
            : alert.timestamp.toString("MMM d, yyyy hh:mm:ss"));

    // ── Status chip (Active / Resolved) ────────────────────────────────
    if (m_statusBadge) {
        const bool resolved = (alert.status == EDR::AlertStatus::Resolved);
        const QString hex   = resolved ? Theme::Color::textMuted
                                          : Theme::Color::severitySafe;
        m_statusBadge->setText(EDR::alertStatusToText(alert.status));
        m_statusBadge->setStyleSheet(QString(
            "QLabel { color: %1; background: transparent;"
            " border: 1px solid %1; border-radius: 6px;"
            " padding: 3px 10px; %2 }")
                .arg(hex)
                .arg(Theme::Type::qss(Theme::Type::Caption,
                                        Theme::Type::WeightSemi)));
        m_statusBadge->setToolTip(resolved && alert.resolvedAt.isValid()
            ? QString("Resolved %1")
                  .arg(alert.resolvedAt.toString("MMM d hh:mm:ss"))
            : QString("Condition observed in the latest tick"));
    }

    // Group banner: prefer the dedup-engine occurrenceCount when it's
    // higher than the UI-side groupCount (the dedup engine accumulates
    // across many ticks, the UI grouping is a 60s window).
    const int totalOccurrences = qMax(alert.occurrenceCount, groupCount);
    if (totalOccurrences > 1 && m_groupBanner) {
        QString msg;
        if (alert.status == EDR::AlertStatus::Resolved) {
            msg = QString("Condition observed across %1 monitoring tick%2 "
                          "before resolving.")
                      .arg(alert.ticksSeen)
                      .arg(alert.ticksSeen == 1 ? "" : "s");
        } else if (alert.ticksSeen > 1) {
            msg = QString("Persistent — observed across %1 monitoring ticks "
                          "(%2 occurrences total).")
                      .arg(alert.ticksSeen).arg(totalOccurrences);
        } else {
            msg = QString("This alert represents %1 occurrences within "
                          "the current grouping window.").arg(totalOccurrences);
        }
        m_groupBanner->setText(msg);
        m_groupBanner->setVisible(true);
    } else if (m_groupBanner) {
        m_groupBanner->setVisible(false);
    }

    // ── Overview ───────────────────────────────────────────────────────
    m_overSummary->setText(alert.description.isEmpty()
                              ? "No summary captured."
                              : alert.description);
    m_overFirstSeen->setText(
        alert.firstSeen.isValid()
            ? alert.firstSeen.toString("MMM d, yyyy hh:mm:ss")
            : alert.timestamp.toString("MMM d, yyyy hh:mm:ss"));
    m_overLastSeen->setText(
        alert.lastSeen.isValid()
            ? alert.lastSeen.toString("MMM d, yyyy hh:mm:ss")
            : alert.timestamp.toString("MMM d, yyyy hh:mm:ss"));
    m_overSource->setText(alert.sourcePath.isEmpty() ? "(unknown)"
                                                       : alert.sourcePath);

    if (alert.pid > 0) {
        QString procText = QString("PID %1").arg(alert.pid);
        if (alert.parentPid > 0)
            procText += QString(" (parent PID %1)").arg(alert.parentPid);
        if (!alert.user.isEmpty())
            procText += QString(" — user %1").arg(alert.user);
        m_overProcess->setText(procText);
        m_overProcess->parentWidget()->setVisible(true);
    } else {
        // Hide the row when there's no process context (hide via setting empty
        // and using a clearer placeholder so the layout stays predictable).
        m_overProcess->setText("(not applicable)");
    }

    // ── Why Flagged ───────────────────────────────────────────────────
    while (QLayoutItem* it = m_whyLayout->takeAt(0)) {
        if (QWidget* w = it->widget()) w->deleteLater();
        delete it;
    }
    QStringList bullets;
    bullets.append(alert.heuristics);
    bullets.append(alert.yaraMatches);
    bullets.removeAll(QString());
    if (bullets.isEmpty()) {
        m_whyEmpty->setVisible(true);
    } else {
        m_whyEmpty->setVisible(false);
        for (const QString& b : bullets) {
            auto* lab = new QLabel(QString::fromUtf8("• ") + b, this);
            lab->setWordWrap(true);
            lab->setStyleSheet(QString(
                "QLabel { color: %1; %2 background: transparent;"
                " line-height: 1.45; }")
                    .arg(Theme::Color::textPrimary)
                    .arg(Theme::Type::qss(Theme::Type::Body)));
            m_whyLayout->addWidget(lab);
        }
    }

    // ── Indicators ─────────────────────────────────────────────────────
    const bool hasTrust = (alert.signingStatus >= 0)
                          || !alert.signerInfo.isEmpty();
    const bool hasHash  = !alert.sha256.isEmpty();
    const bool hasRep   = !alert.reputationFamily.isEmpty();
    if (!hasTrust && !hasHash && !hasRep) {
        m_indEmpty->setVisible(true);
        m_indTrust->setVisible(false);
        m_indHashLabel->setVisible(false);
        m_indHashVal->setVisible(false);
        m_indHashCopy->setVisible(false);
        m_indReputation->setVisible(false);
    } else {
        m_indEmpty->setVisible(false);
        m_indTrust->setVisible(hasTrust);
        m_indHashLabel->setVisible(hasHash);
        m_indHashVal->setVisible(hasHash);
        m_indHashCopy->setVisible(hasHash);
        m_indReputation->setVisible(hasRep);

        if (hasTrust) {
            QString text = trustText(alert.signingStatus);
            if (!alert.signerInfo.isEmpty())
                text += QString(" — %1").arg(alert.signerInfo);
            m_indTrust->setText(QString(
                "<span style='color:%1; font-weight:600;'>%2</span>")
                    .arg(trustHex(alert.signingStatus), text.toHtmlEscaped()));
            m_indTrust->setTextFormat(Qt::RichText);
        }
        if (hasHash) {
            m_indHashVal->setText(abbrevHash(alert.sha256));
            m_indHashVal->setToolTip(alert.sha256);
        }
        if (hasRep)
            m_indReputation->setText(alert.reputationFamily);
    }

    // ── Details ────────────────────────────────────────────────────────
    QString raw = alert.rawDetail;
    if (!alert.cmdline.isEmpty() && !raw.contains("Cmd:"))
        raw += "\nCmd: " + alert.cmdline;
    m_detRaw->setPlainText(raw);
}

// ============================================================================
//  Slots
// ============================================================================
void AlertDetailPanel::onOpenLocationClicked()
{
    if (m_currentAlert.sourcePath.isEmpty()) return;

    // Try to reveal the parent directory containing the source path. If
    // sourcePath is a process name (no separators), there's nothing to
    // open — emit signal so MainWindow can decide.
    QFileInfo fi(m_currentAlert.sourcePath);
    if (fi.exists()) {
        QDesktopServices::openUrl(QUrl::fromLocalFile(
            fi.isDir() ? fi.absoluteFilePath() : fi.absolutePath()));
    } else {
        emit openLocationRequested(m_currentAlert.sourcePath);
    }
}

void AlertDetailPanel::onCopyDetailsClicked()
{
    QGuiApplication::clipboard()->setText(m_currentAlert.rawDetail);
    emit copyDetailsRequested(m_currentAlert.rawDetail);
}

QString AlertDetailPanel::trustText(int signingStatus)
{
    switch (signingStatus) {
        case 2: return "Signed (Trusted)";
        case 1: return "Signed (Untrusted)";
        case 0: return "UNSIGNED";
        default: return "Unknown";
    }
}

const char* AlertDetailPanel::trustHex(int signingStatus)
{
    switch (signingStatus) {
        case 2:  return "#10B981";
        case 1:  return "#F59E0B";
        case 0:  return "#EF4444";
        default: return Theme::Color::textSecondary;
    }
}

// ============================================================================
//  Phase 5 — Response & Control Layer slots
// ============================================================================
void AlertDetailPanel::onQuarantineClicked()
{
    namespace R = odysseus::response;
    if (m_currentAlert.sourcePath.isEmpty()) return;

    const QFileInfo fi(m_currentAlert.sourcePath);
    if (!fi.isFile()) {
        QMessageBox::warning(this, "Quarantine",
            "This alert does not point at a regular file.");
        return;
    }

    QMessageBox box(this);
    box.setIcon(QMessageBox::Warning);
    box.setWindowTitle("Quarantine file");
    box.setText("Move this file to quarantine?");
    box.setInformativeText(QString(
        "<b>%1</b><br><br><i>%2</i><br><br>"
        "The file will be moved (not deleted) to the Odysseus quarantine "
        "directory with read-only permissions. You can restore it later "
        "from the Quarantine page. This action will be recorded in the "
        "action log.")
            .arg(fi.fileName().toHtmlEscaped(),
                 m_currentAlert.sourcePath.toHtmlEscaped()));
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
    box.setDefaultButton(QMessageBox::Cancel);
    if (box.exec() != QMessageBox::Yes) return;

    R::ActionRequest req;
    req.action          = R::ActionType::QuarantineFile;
    req.userConfirmed   = true;
    req.target.kind     = R::TargetKind::File;
    req.target.path     = m_currentAlert.sourcePath.toStdString();
    req.target.sha256   = m_currentAlert.sha256.toStdString();
    req.target.label    = fi.fileName().toStdString();
    req.target.sourceId = m_currentAlert.id.toStdString();
    req.reason          = std::string("Quarantine via Alerts page (alert: ")
                          + m_currentAlert.title.toStdString() + ")";

    R::ActionResult res = R::globalResponseManager().execute(req);

    if (res.success) {
        QMessageBox::information(this, "Quarantine",
            QString("File quarantined.\n\nMoved to:\n%1")
                .arg(QString::fromStdString(res.newPath)));
        if (m_btnQuarantine) m_btnQuarantine->setEnabled(false);
        if (m_btnIgnore)     m_btnIgnore->setEnabled(false);
    } else {
        const std::string err = res.errorMessage.empty() ? res.message
                                                          : res.errorMessage;
        QMessageBox::critical(this, "Quarantine failed",
            QString::fromStdString(err));
    }
}

void AlertDetailPanel::onIgnoreClicked()
{
    namespace R = odysseus::response;

    // Pick the right TargetKind + Allowlist field based on the alert
    // category. ResponseManager::executeAddToAllowlist consults sha256
    // first, then path, then signatureKey — which is exactly the
    // "prefer SHA-256" ordering the spec asks for.
    R::ActionRequest req;
    req.action        = R::ActionType::AddToAllowlist;
    req.userConfirmed = true;
    req.reason        = std::string("Ignore via Alerts page (alert: ")
                        + m_currentAlert.title.toStdString() + ")";

    const QString cat = m_currentAlert.category;
    QString idLine;
    if (cat == EDR::Category::Process) {
        req.target.kind          = R::TargetKind::Process;
        req.target.path          = m_currentAlert.sourcePath.toStdString();
        req.target.processName   = m_currentAlert.sourcePath.toStdString();
        idLine = "Process path: " + m_currentAlert.sourcePath;
    } else if (cat == EDR::Category::Persistence) {
        req.target.kind  = R::TargetKind::Persistence;
        req.target.path  = m_currentAlert.sourcePath.toStdString();
        req.target.label = m_currentAlert.title.toStdString();
        idLine = m_currentAlert.sourcePath.isEmpty()
                    ? QString("Label: %1").arg(m_currentAlert.title)
                    : QString("Path: %1").arg(m_currentAlert.sourcePath);
    } else if (cat == EDR::Category::Integrity || !m_currentAlert.sha256.isEmpty()) {
        // Integrity alerts always have a sha256 + a file path; prefer
        // sha256 (matches everywhere the file exists).
        req.target.kind   = R::TargetKind::File;
        req.target.path   = m_currentAlert.sourcePath.toStdString();
        req.target.sha256 = m_currentAlert.sha256.toStdString();
        idLine = m_currentAlert.sha256.isEmpty()
                    ? QString("Path: %1").arg(m_currentAlert.sourcePath)
                    : QString("SHA-256: %1").arg(m_currentAlert.sha256);
    } else {
        // Cross-view, kernel-extension, service, etc. — use the alert
        // signature (category + sourcePath) as the dedup key.
        req.target.kind         = R::TargetKind::Unknown;
        req.target.signatureKey =
            QString("%1::%2").arg(cat, m_currentAlert.sourcePath).toStdString();
        idLine = QString("Signature: %1::%2")
                     .arg(cat, m_currentAlert.sourcePath);
    }

    QMessageBox box(this);
    box.setIcon(QMessageBox::Question);
    box.setWindowTitle("Add to allowlist");
    box.setText("Suppress future alerts for this item?");
    box.setInformativeText(QString(
        "<b>%1</b><br><br>%2<br><br>"
        "This entry will be visible (and removable) in Settings → Allowlist.")
            .arg(m_currentAlert.title.toHtmlEscaped(), idLine.toHtmlEscaped()));
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
    box.setDefaultButton(QMessageBox::Cancel);
    if (box.exec() != QMessageBox::Yes) return;

    R::ActionResult res = R::globalResponseManager().execute(req);

    if (res.success) {
        QMessageBox::information(this, "Allowlisted",
            QString("Added to allowlist.\n\n%1")
                .arg(QString::fromStdString(res.message)));
        if (m_btnIgnore) m_btnIgnore->setEnabled(false);
    } else {
        const std::string err = res.errorMessage.empty() ? res.message
                                                          : res.errorMessage;
        QMessageBox::critical(this, "Allowlist failed",
            QString::fromStdString(err));
    }
}
