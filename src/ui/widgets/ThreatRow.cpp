// ============================================================================
// ThreatRow.cpp
// ============================================================================

#include "ThreatRow.h"

#include <QFontMetrics>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QMouseEvent>
#include <QVBoxLayout>

#include "../theme/DashboardTheme.h"

namespace {

const char* severityHex(const QString& sev) {
  const QString s = sev.toLower();
  if (s == "critical")
    return Theme::Color::severityCritical;
  if (s == "clean" || s == "safe")
    return Theme::Color::severitySafe;
  // suspicious / needs-review / anything else → amber
  return Theme::Color::severityMedium;
}

QString severityLabel(const QString& sev) {
  const QString s = sev.toLower();
  if (s == "critical")
    return "Critical";
  if (s == "needs-review")
    return "Needs Review";
  if (s == "clean")
    return "Clean";
  return "Suspicious";
}

QString truncatePath(const QString& s, int max = 56) {
  if (s.length() <= max)
    return s;
  return QString::fromUtf8("\xE2\x80\xA6") + s.right(max - 1);  // …
}

}  // namespace

ThreatRow::ThreatRow(QWidget* parent)
    : QFrame(parent) {
  setObjectName("OdyThreatRow");
  setAttribute(Qt::WA_StyledBackground, true);
  setCursor(Qt::PointingHandCursor);
  setMinimumHeight(76);

  auto* h = new QHBoxLayout(this);
  // Linear/Vercel-style card: more breathing room than a table row.
  h->setContentsMargins(20, 16, 20, 16);
  h->setSpacing(20);

  // ── Severity dot ───────────────────────────────────────────────────
  m_dot = new QLabel(this);
  m_dot->setFixedSize(10, 10);
  m_dot->setStyleSheet(QString("QLabel { background-color: %1; border-radius: 5px; }")
                           .arg(Theme::Color::severityMedium));
  h->addWidget(m_dot, 0, Qt::AlignVCenter);

  // ── THREAT column (name + subtext) ─────────────────────────────────
  auto* nameCol = new QVBoxLayout();
  nameCol->setContentsMargins(0, 0, 0, 0);
  nameCol->setSpacing(2);

  m_name = new QLabel("—", this);
  m_name->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                            .arg(Theme::Color::textPrimary)
                            .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi)));
  nameCol->addWidget(m_name);

  m_subtext = new QLabel("", this);
  m_subtext->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                               .arg(Theme::Color::textSecondary)
                               .arg(Theme::Type::qss(Theme::Type::Caption)));
  nameCol->addWidget(m_subtext);

  auto* nameWrap = new QWidget(this);
  nameWrap->setLayout(nameCol);
  nameWrap->setStyleSheet("background: transparent;");
  h->addWidget(nameWrap, 4);

  // ── SEVERITY badge ─────────────────────────────────────────────────
  m_severityBadge = new QLabel("—", this);
  m_severityBadge->setAlignment(Qt::AlignCenter);
  m_severityBadge->setMinimumWidth(86);
  m_severityBadge->setMaximumWidth(110);
  h->addWidget(m_severityBadge, 0, Qt::AlignVCenter);

  // ── CONFIDENCE: number + bar ───────────────────────────────────────
  auto* confCol = new QVBoxLayout();
  confCol->setContentsMargins(0, 0, 0, 0);
  confCol->setSpacing(4);

  m_confidenceNum = new QLabel("0.000", this);
  m_confidenceNum->setStyleSheet(
      QString("QLabel { color: %1; %2 background: transparent;"
              " font-family: monospace; }")
          .arg(Theme::Color::textPrimary)
          .arg(Theme::Type::qss(Theme::Type::Small, Theme::Type::WeightSemi)));
  confCol->addWidget(m_confidenceNum);

  m_confidenceBar = new QFrame(this);
  m_confidenceBar->setFixedHeight(4);
  m_confidenceBar->setStyleSheet(QString("QFrame { background-color: %1; border-radius: 2px; }")
                                     .arg(Theme::Color::borderSubtle));
  auto* fillLayout = new QHBoxLayout(m_confidenceBar);
  fillLayout->setContentsMargins(0, 0, 0, 0);
  fillLayout->setSpacing(0);
  m_confidenceFill = new QFrame(m_confidenceBar);
  m_confidenceFill->setFixedHeight(4);
  m_confidenceFill->setStyleSheet(QString("QFrame { background-color: %1; border-radius: 2px; }")
                                      .arg(Theme::Color::severityCritical));
  fillLayout->addWidget(m_confidenceFill);
  fillLayout->addStretch();
  confCol->addWidget(m_confidenceBar);

  auto* confWrap = new QWidget(this);
  confWrap->setLayout(confCol);
  confWrap->setStyleSheet("background: transparent;");
  confWrap->setFixedWidth(120);
  h->addWidget(confWrap, 0, Qt::AlignVCenter);

  // ── SOURCE column ──────────────────────────────────────────────────
  m_source = new QLabel("—", this);
  m_source->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                              .arg(Theme::Color::textSecondary)
                              .arg(Theme::Type::qss(Theme::Type::Small)));
  m_source->setFixedWidth(90);
  h->addWidget(m_source, 0, Qt::AlignVCenter);

  // ── DETECTED column ────────────────────────────────────────────────
  m_detected = new QLabel("—", this);
  m_detected->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                                .arg(Theme::Color::textSecondary)
                                .arg(Theme::Type::qss(Theme::Type::Small)));
  m_detected->setFixedWidth(120);
  h->addWidget(m_detected, 0, Qt::AlignVCenter);

  // ── STATUS badge (outlined, subtle — Linear-style) ─────────────────
  m_statusBadge = new QLabel("Detected", this);
  m_statusBadge->setAlignment(Qt::AlignCenter);
  m_statusBadge->setMinimumWidth(82);
  m_statusBadge->setStyleSheet(
      QString("QLabel { color: %1; background: transparent;"
              " border: 1px solid %1; border-radius: 6px;"
              " padding: 3px 10px; %2 }")
          .arg(Theme::Color::accentBlue)
          .arg(Theme::Type::qss(Theme::Type::Caption, Theme::Type::WeightSemi)));
  h->addWidget(m_statusBadge, 0, Qt::AlignVCenter);

  // ── Chevron (›) ────────────────────────────────────────────────────
  // Single unicode RIGHT SINGLE GUILLEMET — not an emoji.
  m_chevron = new QLabel(QString::fromUtf8("\xE2\x80\xBA"), this);
  m_chevron->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent;"
                                   " padding-left: 6px; }")
                               .arg(Theme::Color::textMuted)
                               .arg(Theme::Type::qss(Theme::Type::H2)));
  m_chevron->setFixedWidth(20);
  h->addWidget(m_chevron, 0, Qt::AlignVCenter);

  setSeverity("needs-review");
  applyVisualState();
}

// ============================================================================
//  Setters
// ============================================================================
void ThreatRow::setSeverity(const QString& severity) {
  m_severity = severity;

  const QString hex = severityHex(severity);
  m_dot->setStyleSheet(QString("QLabel { background-color: %1; border-radius: 5px; }").arg(hex));

  // Outlined severity badge — colored 1px border + colored text on
  // transparent bg. No bright color blocks; reads as a subtle tag.
  m_severityBadge->setText(severityLabel(severity));
  m_severityBadge->setStyleSheet(
      QString("QLabel { color: %1; background: transparent;"
              " border: 1px solid %1; border-radius: 6px;"
              " padding: 3px 10px; %2 }")
          .arg(hex)
          .arg(Theme::Type::qss(Theme::Type::Caption, Theme::Type::WeightSemi)));

  m_confidenceFill->setStyleSheet(
      QString("QFrame { background-color: %1; border-radius: 2px; }").arg(hex));
}

void ThreatRow::setThreatName(const QString& name) {
  m_name->setText(name.isEmpty() ? "(no name)" : name);
}

void ThreatRow::setSubtext(const QString& s) {
  m_subtext->setText(truncatePath(s, 80));
  m_subtext->setToolTip(s);
}

void ThreatRow::setConfidence(float zeroToOne) {
  const float clamped = qBound(0.0f, zeroToOne, 1.0f);
  m_confidenceNum->setText(QString::number(clamped, 'f', 3));

  // Compute fill width relative to the bar's track. We can't lay it out
  // proportionally inside the QHBoxLayout so easily, so we fix the fill
  // width manually based on the bar's current fixed width.
  const int trackWidth = m_confidenceBar->width() > 0 ? m_confidenceBar->width() : 120;
  m_confidenceFill->setFixedWidth(static_cast<int>(trackWidth * clamped));
}

void ThreatRow::setSource(const QString& s) {
  m_source->setText(s);
}
void ThreatRow::setDetected(const QString& s) {
  m_detected->setText(s);
}
void ThreatRow::setStatus(const QString& s) {
  m_statusBadge->setText(s);
}

void ThreatRow::setSelected(bool sel) {
  if (m_selected == sel)
    return;
  m_selected = sel;
  applyVisualState();
}

// ============================================================================
//  Hover / click
// ============================================================================
void ThreatRow::mouseReleaseEvent(QMouseEvent* e) {
  if (e->button() == Qt::LeftButton && rect().contains(e->pos()))
    emit clicked(m_payload);
  QFrame::mouseReleaseEvent(e);
}

void ThreatRow::enterEvent(QEnterEvent* e) {
  m_hovered = true;
  applyVisualState();
  QFrame::enterEvent(e);
}

void ThreatRow::leaveEvent(QEvent* e) {
  m_hovered = false;
  applyVisualState();
  QFrame::leaveEvent(e);
}

void ThreatRow::applyVisualState() {
  // Card-style row: always has a subtle bg, no per-row outer border
  // (the spacing between rows in the parent layout does the visual
  // separation). Hover lifts the bg one notch; selected adds a
  // severity-colored 3px left accent + the same lifted bg.
  QString bg = Theme::Color::bgCard;
  QString leftAccent = "transparent";

  if (m_selected) {
    bg = Theme::Color::bgCardHover;
    leftAccent = severityHex(m_severity);
  } else if (m_hovered) {
    bg = Theme::Color::bgCardHover;
  }

  setStyleSheet(QString("QFrame#OdyThreatRow {"
                        "  background-color: %1;"
                        "  border: none;"
                        "  border-left: 3px solid %2;"
                        "  border-radius: 10px;"
                        "}")
                    .arg(bg, leftAccent));
}
