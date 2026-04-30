// ============================================================================
// AlertRow.cpp
// ============================================================================

#include "AlertRow.h"
#include "SeverityBadge.h"
#include "../theme/DashboardTheme.h"

#include <QLabel>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QMouseEvent>
#include <QDateTime>

namespace {

QString relTime(const QDateTime& when)
{
    if (!when.isValid()) return "—";
    const qint64 secs = when.secsTo(QDateTime::currentDateTime());
    if (secs < 5)         return "just now";
    if (secs < 60)        return QString("%1s ago").arg(secs);
    if (secs < 60*60)     return QString("%1m ago").arg(secs / 60);
    if (secs < 60*60*24)  return QString("%1h ago").arg(secs / 3600);
    return when.toString("MMM d");
}

const char* severityHexFor(EDR::Severity s)
{
    switch (s) {
        case EDR::Severity::Critical: return "#EF4444";
        case EDR::Severity::High:     return "#F97316";
        case EDR::Severity::Medium:   return "#F59E0B";
        case EDR::Severity::Low:      return Theme::Color::accentBlue;
        case EDR::Severity::Info:     return Theme::Color::textSecondary;
    }
    return Theme::Color::textSecondary;
}

}  // anonymous

const char* AlertRow::iconForCategory(const QString& cat)
{
    // Small text glyphs (no emoji) per the strict-no-emoji rule.
    //   Process     ▶
    //   Persistence ◎
    //   Integrity   ⬢
    //   Kext        ⛨
    //   CrossView   ⇄
    //   Service     ◆
    if (cat == EDR::Category::Process)     return "\xE2\x96\xB6";
    if (cat == EDR::Category::Persistence) return "\xE2\x97\x8E";
    if (cat == EDR::Category::Integrity)   return "\xE2\xAC\xA2";
    if (cat == EDR::Category::KernelExt)   return "\xE2\x9B\xA8";
    if (cat == EDR::Category::CrossView)   return "\xE2\x87\x84";
    return "\xE2\x97\x86";
}

QString AlertRow::smartTruncate(const QString& path, int maxLen)
{
    if (path.length() <= maxLen) return path;

    // Detect filesystem-style paths so we can keep the leaf + first
    // segment ("/Users/.../leaf-dir/leaf-file.ext").
    if (path.contains('/') || path.contains('\\')) {
        const QString sep = path.contains('/') ? "/" : "\\";
        const QStringList parts = path.split(sep, Qt::SkipEmptyParts);
        if (parts.size() >= 3) {
            const QString head = parts.first();
            const QString tail = parts.last();
            const QString tailParent = parts[parts.size() - 2];
            const QString prefix = path.startsWith(sep) ? sep : QString();
            QString shortened = prefix + head + sep + "..." + sep
                                + tailParent + sep + tail;
            if (shortened.length() <= maxLen) return shortened;
        }
    }
    // Fallback: keep the right (filename-y) portion.
    return "..." + path.right(maxLen - 3);
}

// ============================================================================
//  Construction
// ============================================================================
AlertRow::AlertRow(QWidget* parent)
    : QFrame(parent)
{
    setObjectName("OdyAlertRow");
    setAttribute(Qt::WA_StyledBackground, true);
    setCursor(Qt::PointingHandCursor);
    setMinimumHeight(64);

    auto* h = new QHBoxLayout(this);
    h->setContentsMargins(16, 12, 16, 12);
    h->setSpacing(14);

    // ── Severity dot (always visible for at-a-glance triage) ───────────
    m_dot = new QLabel(this);
    m_dot->setFixedSize(8, 8);
    m_dot->setStyleSheet(QString(
        "QLabel { background-color: %1; border-radius: 4px; }")
            .arg(Theme::Color::textSecondary));
    h->addWidget(m_dot, 0, Qt::AlignVCenter);

    // ── Time ───────────────────────────────────────────────────────────
    m_timeLab = new QLabel("—", this);
    m_timeLab->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent; }")
            .arg(Theme::Color::textMuted)
            .arg(Theme::Type::qss(Theme::Type::Caption)));
    m_timeLab->setFixedWidth(72);
    h->addWidget(m_timeLab, 0, Qt::AlignVCenter);

    // ── Category column (icon + label) ────────────────────────────────
    auto* catCol = new QHBoxLayout();
    catCol->setContentsMargins(0, 0, 0, 0);
    catCol->setSpacing(6);
    m_categoryIcon = new QLabel(this);
    m_categoryIcon->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent; }")
            .arg(Theme::Color::textSecondary)
            .arg(Theme::Type::qss(Theme::Type::Body)));
    catCol->addWidget(m_categoryIcon);
    m_categoryLab = new QLabel(this);
    m_categoryLab->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent;"
        " text-transform: uppercase; letter-spacing: 0.5px; }")
            .arg(Theme::Color::textSecondary)
            .arg(Theme::Type::qss(Theme::Type::Caption,
                                    Theme::Type::WeightSemi)));
    catCol->addWidget(m_categoryLab);
    auto* catWrap = new QWidget(this);
    catWrap->setLayout(catCol);
    catWrap->setStyleSheet("background: transparent;");
    catWrap->setFixedWidth(120);
    h->addWidget(catWrap, 0, Qt::AlignVCenter);

    // ── Title + Source column (stretches) ──────────────────────────────
    auto* col = new QVBoxLayout();
    col->setSpacing(2);
    col->setContentsMargins(0, 0, 0, 0);
    m_titleLab = new QLabel("—", this);
    m_titleLab->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent; }")
            .arg(Theme::Color::textPrimary)
            .arg(Theme::Type::qss(Theme::Type::Body,
                                    Theme::Type::WeightSemi)));
    col->addWidget(m_titleLab);
    m_sourceLab = new QLabel("", this);
    m_sourceLab->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent; }")
            .arg(Theme::Color::textSecondary)
            .arg(Theme::Type::qss(Theme::Type::Caption)));
    col->addWidget(m_sourceLab);
    auto* colWrap = new QWidget(this);
    colWrap->setStyleSheet("background: transparent;");
    colWrap->setLayout(col);
    h->addWidget(colWrap, 1);

    // ── Severity badge (outlined) ─────────────────────────────────────
    m_badge = new SeverityBadge(this);
    h->addWidget(m_badge, 0, Qt::AlignVCenter);

    // ── Chevron (›) ────────────────────────────────────────────────────
    m_chevron = new QLabel(QString::fromUtf8("\xE2\x80\xBA"), this);
    m_chevron->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent;"
        " padding-left: 6px; }")
            .arg(Theme::Color::textMuted)
            .arg(Theme::Type::qss(Theme::Type::H2)));
    m_chevron->setFixedWidth(18);
    h->addWidget(m_chevron, 0, Qt::AlignVCenter);

    applyStyle();
}

// ============================================================================
//  Public API
// ============================================================================
void AlertRow::setAlert(const EDR::Alert& alert,
                          int               index,
                          int               occurrenceCount,
                          bool              isGroupHeader)
{
    m_severity = alert.severity;
    m_index    = index;
    m_isGroup  = isGroupHeader && occurrenceCount > 1;
    m_resolved = (alert.status == EDR::AlertStatus::Resolved);

    // Severity dot color (muted when the condition has resolved)
    const QString dotHex = m_resolved
                              ? QString(Theme::Color::textMuted)
                              : QString(severityHexFor(alert.severity));
    m_dot->setStyleSheet(QString(
        "QLabel { background-color: %1; border-radius: 4px; }").arg(dotHex));

    m_timeLab->setText(relTime(alert.lastSeen.isValid()
                                ? alert.lastSeen
                                : alert.timestamp));
    m_categoryIcon->setText(QString::fromUtf8(iconForCategory(alert.category)));
    m_categoryLab->setText(alert.category);

    QString title = alert.title;
    if (m_resolved)
        title = QString("[Resolved] %1").arg(title);
    else if (m_isGroup)
        title = QString("%1 — %2 occurrences").arg(title).arg(occurrenceCount);
    else if (alert.ticksSeen > 1)
        title = QString("%1 (×%2 ticks)").arg(title).arg(alert.ticksSeen);
    m_titleLab->setText(title);

    m_sourceLab->setText(smartTruncate(alert.sourcePath, 70));
    m_sourceLab->setToolTip(alert.sourcePath);

    m_badge->setSeverity(alert.severity);
    m_badge->setBadgeStyle(SeverityBadge::Outlined);

    applyStyle();
}

void AlertRow::setSelected(bool sel)
{
    if (m_selected == sel) return;
    m_selected = sel;
    applyStyle();
}

void AlertRow::setZebra(bool z)
{
    m_zebra = z;
    applyStyle();
}

void AlertRow::mouseReleaseEvent(QMouseEvent* e)
{
    if (e->button() == Qt::LeftButton && rect().contains(e->pos()))
        emit clicked(m_index);
    QFrame::mouseReleaseEvent(e);
}

void AlertRow::enterEvent(QEnterEvent* e)
{
    m_hovered = true;
    applyStyle();
    QFrame::enterEvent(e);
}

void AlertRow::leaveEvent(QEvent* e)
{
    m_hovered = false;
    applyStyle();
    QFrame::leaveEvent(e);
}

void AlertRow::applyStyle()
{
    QString bg     = m_zebra ? Theme::Color::bgSecondary
                              : Theme::Color::bgCard;
    QString left   = "transparent";

    if (m_selected) {
        bg   = Theme::Color::bgCardHover;
        left = m_resolved ? QString(Theme::Color::textMuted)
                           : QString(severityHexFor(m_severity));
    } else if (m_hovered) {
        bg   = Theme::Color::bgCardHover;
    }

    // Visually de-emphasize resolved rows by muting the title + source
    // text colors (resolved alerts are history, not active risk).
    if (m_titleLab) {
        m_titleLab->setStyleSheet(QString(
            "QLabel { color: %1; %2 background: transparent; }")
                .arg(m_resolved
                        ? QString(Theme::Color::textMuted)
                        : QString(Theme::Color::textPrimary))
                .arg(Theme::Type::qss(Theme::Type::Body,
                                        Theme::Type::WeightSemi)));
    }
    if (m_sourceLab) {
        m_sourceLab->setStyleSheet(QString(
            "QLabel { color: %1; %2 background: transparent; }")
                .arg(m_resolved
                        ? QString(Theme::Color::textMuted)
                        : QString(Theme::Color::textSecondary))
                .arg(Theme::Type::qss(Theme::Type::Caption)));
    }

    setStyleSheet(QString(
        "QFrame#OdyAlertRow {"
        "  background-color: %1;"
        "  border: none;"
        "  border-left: 3px solid %2;"
        "  border-radius: 8px;"
        "}"
    ).arg(bg, left));
}
