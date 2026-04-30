// ============================================================================
// StatCard.cpp
//
// Layout:
//   ┌───────────────────────────────┐
//   │ Title text          icon glyph│
//   │ HUGE VALUE                    │
//   │ subtitle text                 │
//   │ ───────────  (pulse bar)      │
//   └───────────────────────────────┘
// ============================================================================

#include "StatCard.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QVBoxLayout>

#include "../theme/DashboardTheme.h"

StatCard::StatCard(QWidget* parent)
    : QFrame(parent) {
  setObjectName("OdyStatCard");
  setAttribute(Qt::WA_StyledBackground, true);
  setFrameShape(QFrame::NoFrame);
  setMinimumHeight(120);

  auto* v = new QVBoxLayout(this);
  v->setContentsMargins(20, 16, 20, 16);
  v->setSpacing(6);

  // ── Title row: text on the left, icon glyph on the right ───────────
  auto* topRow = new QHBoxLayout();
  topRow->setContentsMargins(0, 0, 0, 0);

  m_titleLabel = new QLabel("—", this);
  m_titleLabel->setStyleSheet("font-size: 12px; font-weight: 600; letter-spacing: 0.3px;");
  topRow->addWidget(m_titleLabel);
  topRow->addStretch(1);

  m_iconLabel = new QLabel(QString(), this);
  m_iconLabel->setStyleSheet("font-size: 22px;");
  topRow->addWidget(m_iconLabel);

  v->addLayout(topRow);

  // ── Big value ──────────────────────────────────────────────────────
  m_valueLabel = new QLabel("—", this);
  m_valueLabel->setStyleSheet(
      QString("color: %1; font-size: 26px; font-weight: 700;").arg(Theme::Color::textPrimary));
  v->addWidget(m_valueLabel);

  // ── Subtitle ───────────────────────────────────────────────────────
  m_subtitleLabel = new QLabel("", this);
  m_subtitleLabel->setStyleSheet(
      QString("color: %1; font-size: 11px;").arg(Theme::Color::textSecondary));
  m_subtitleLabel->setWordWrap(true);
  v->addWidget(m_subtitleLabel);

  v->addStretch(1);

  // ── Decorative pulse bar at the bottom ─────────────────────────────
  m_pulseBar = new QFrame(this);
  m_pulseBar->setFixedHeight(3);
  m_pulseBar->setFrameShape(QFrame::NoFrame);
  v->addWidget(m_pulseBar);

  applyTone();
}

void StatCard::setTone(Tone tone) {
  m_tone = tone;
  applyTone();
}

void StatCard::setTitle(const QString& s) {
  m_titleLabel->setText(s);
}
void StatCard::setValue(const QString& s) {
  m_valueLabel->setText(s);
}
void StatCard::setSubtitle(const QString& s) {
  m_subtitleLabel->setText(s);
}
void StatCard::setIcon(const QString& g) {
  m_iconLabel->setText(g);
}

void StatCard::applyTone() {
  QString accent;
  switch (m_tone) {
    case Safe:
      accent = Theme::Color::severitySafe;
      break;
    case Critical:
      accent = Theme::Color::severityCritical;
      break;
    case Warning:
      accent = Theme::Color::severityMedium;
      break;
    case Info:
    default:
      accent = Theme::Color::accentBlue;
      break;
  }

  setStyleSheet(QString("QFrame#OdyStatCard {"
                        "  background-color: %1;"
                        "  border: 1px solid %2;"
                        "  border-radius: %3px;"
                        "}")
                    .arg(Theme::Color::bgCard)
                    .arg(Theme::Color::borderSubtle)
                    .arg(Theme::Size::cardRadius));

  m_titleLabel->setStyleSheet(QString("color: %1; font-size: 12px; font-weight: 600;"
                                      " letter-spacing: 0.3px;")
                                  .arg(accent));

  m_iconLabel->setStyleSheet(QString("color: %1; font-size: 22px;").arg(accent));

  // Gradient pulse bar from accent → transparent for a subtle polish detail
  m_pulseBar->setStyleSheet(QString("QFrame {"
                                    "  background: qlineargradient(x1:0, y1:0, x2:1, y2:0,"
                                    "    stop:0 %1, stop:1 transparent);"
                                    "  border-radius: 1.5px;"
                                    "}")
                                .arg(accent));
}
