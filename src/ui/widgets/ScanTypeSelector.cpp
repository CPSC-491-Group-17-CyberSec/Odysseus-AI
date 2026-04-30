// ============================================================================
// ScanTypeSelector.cpp
//
// Cards are styled QFrames. We intercept QEvent::MouseButtonRelease via this
// widget's eventFilter() so any of the three card frames can select itself
// without needing a custom QFrame subclass with its own clicked() signal.
// ============================================================================

#include "ScanTypeSelector.h"

#include <QEvent>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QMouseEvent>
#include <QPushButton>
#include <QVBoxLayout>

#include "../theme/DashboardTheme.h"

ScanTypeSelector::ScanTypeSelector(QWidget* parent)
    : QFrame(parent) {
  setObjectName("OdyScanTypeSelector");
  setAttribute(Qt::WA_StyledBackground, true);
  setStyleSheet(QString("QFrame#OdyScanTypeSelector {"
                        "  background-color: %1;"
                        "  border: 1px solid %2;"
                        "  border-radius: %3px;"
                        "}")
                    .arg(Theme::Color::bgCard, Theme::Color::borderSubtle)
                    .arg(Theme::Size::cardRadius));

  auto* outer = new QVBoxLayout(this);
  outer->setContentsMargins(20, 18, 20, 18);
  outer->setSpacing(14);

  auto* title = new QLabel("Start a New Scan", this);
  title->setStyleSheet(
      QString("color: %1; font-size: 18px; font-weight: 700;").arg(Theme::Color::textPrimary));
  outer->addWidget(title);

  auto* sub = new QLabel("Choose your scan type and protect your system", this);
  sub->setStyleSheet(QString("color: %1; font-size: 12px;").arg(Theme::Color::textSecondary));
  outer->addWidget(sub);

  // ── Three cards in a row ────────────────────────────────────────────
  auto* row = new QHBoxLayout();
  row->setSpacing(10);

  m_cards[0] = buildCard(
      Quick,
      QString::fromUtf8("\xE2\x9A\xA1"),  // ⚡
      "Quick Scan",
      "Scan critical areas",
      "~ 5 min");
  m_cards[1] = buildCard(
      Full,
      QString::fromUtf8("\xE2\x96\xA6"),  // ▦
      "Full Scan",
      "Deep system scan",
      "~ 30-60 min");
  m_cards[2] = buildCard(
      Custom,
      QString::fromUtf8("\xE2\x9A\x99"),  // ⚙
      "Custom Scan",
      "Choose what to scan",
      "Custom");

  for (int i = 0; i < 3; ++i)
    row->addWidget(m_cards[i].frame, 1);
  outer->addLayout(row);

  // ── Start button ───────────────────────────────────────────────────
  m_startBtn = new QPushButton(QString::fromUtf8("\xE2\x96\xB6  Start Quick Scan"), this);
  m_startBtn->setCursor(Qt::PointingHandCursor);
  m_startBtn->setFixedHeight(42);
  m_startBtn->setStyleSheet(QString("QPushButton {"
                                    "  background-color: %1; color: white; border: none;"
                                    "  border-radius: 10px; font-size: 14px; font-weight: 600;"
                                    "}"
                                    "QPushButton:hover { background-color: %2; }")
                                .arg(Theme::Color::accentBlue, Theme::Color::accentBlueHover));
  outer->addWidget(m_startBtn);

  connect(m_startBtn, &QPushButton::clicked, this, &ScanTypeSelector::onStartClicked);

  setSelected(Quick);
}

ScanTypeSelector::Card ScanTypeSelector::buildCard(
    ScanType type,
    const QString& glyph,
    const QString& title,
    const QString& subtitle,
    const QString& estimate) {
  Card c;
  c.type = type;
  c.frame = new QFrame(this);
  c.frame->setObjectName("OdyScanTypeCard");
  c.frame->setAttribute(Qt::WA_StyledBackground, true);
  c.frame->setCursor(Qt::PointingHandCursor);
  c.frame->setMinimumHeight(140);
  c.frame->setProperty("__scanType", static_cast<int>(type));
  c.frame->installEventFilter(this);

  auto* v = new QVBoxLayout(c.frame);
  v->setContentsMargins(14, 14, 14, 14);
  v->setSpacing(4);

  c.glyph = new QLabel(glyph, c.frame);
  c.glyph->setStyleSheet("font-size: 26px;");
  v->addWidget(c.glyph);

  c.title = new QLabel(title, c.frame);
  c.title->setStyleSheet(
      QString("color: %1; font-size: 14px; font-weight: 700;").arg(Theme::Color::textPrimary));
  v->addWidget(c.title);

  c.subtitle = new QLabel(subtitle, c.frame);
  c.subtitle->setStyleSheet(
      QString("color: %1; font-size: 11px;").arg(Theme::Color::textSecondary));
  v->addWidget(c.subtitle);

  v->addStretch(1);

  c.estimate = new QLabel(estimate, c.frame);
  c.estimate->setStyleSheet(
      QString("color: %1; font-size: 11px; font-weight: 600;").arg(Theme::Color::accentBlue));
  v->addWidget(c.estimate);

  styleCard(c, false);
  return c;
}

void ScanTypeSelector::styleCard(Card& c, bool selected) {
  const QString border = selected ? Theme::Color::accentBlue : Theme::Color::borderSubtle;
  const QString bg = selected ? Theme::Color::accentBlueSoft : Theme::Color::bgPrimary;

  c.frame->setStyleSheet(QString("QFrame#OdyScanTypeCard {"
                                 "  background-color: %1;"
                                 "  border: 2px solid %2;"
                                 "  border-radius: %3px;"
                                 "}")
                             .arg(bg, border)
                             .arg(Theme::Size::cardRadius));
}

void ScanTypeSelector::setSelected(ScanType type) {
  m_selected = type;
  for (int i = 0; i < 3; ++i)
    styleCard(m_cards[i], m_cards[i].type == type);

  QString label;
  switch (type) {
    case Quick:
      label = QString::fromUtf8("\xE2\x96\xB6  Start Quick Scan");
      break;
    case Full:
      label = QString::fromUtf8("\xE2\x96\xB6  Start Full Scan");
      break;
    case Custom:
      label = QString::fromUtf8("\xE2\x96\xB6  Start Custom Scan");
      break;
  }
  if (m_startBtn)
    m_startBtn->setText(label);
}

void ScanTypeSelector::onCardClicked() {
  // Hooks via eventFilter — never called directly. Kept so the MOC slot
  // table stays stable even if we add a direct connect later.
}

void ScanTypeSelector::onStartClicked() {
  emit scanRequested(static_cast<int>(m_selected));
}

bool ScanTypeSelector::eventFilter(QObject* watched, QEvent* event) {
  if (event->type() == QEvent::MouseButtonRelease) {
    auto* frame = qobject_cast<QFrame*>(watched);
    if (frame && frame->property("__scanType").isValid()) {
      auto* me = static_cast<QMouseEvent*>(event);
      if (me->button() == Qt::LeftButton) {
        const int t = frame->property("__scanType").toInt();
        setSelected(static_cast<ScanType>(t));
        return true;
      }
    }
  }
  return QFrame::eventFilter(watched, event);
}
