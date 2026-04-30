// ============================================================================
// ToggleRow.cpp
// ============================================================================

#include "ToggleRow.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QMouseEvent>
#include <QPainter>
#include <QVBoxLayout>

#include "../theme/DashboardTheme.h"

// ---------------------------------------------------------------------------
// ToggleSwitch
// ---------------------------------------------------------------------------
ToggleSwitch::ToggleSwitch(QWidget* parent)
    : QWidget(parent) {
  setCursor(Qt::PointingHandCursor);
  setAttribute(Qt::WA_Hover, true);
  setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
}

QSize ToggleSwitch::sizeHint() const {
  return QSize(40, 22);
}

void ToggleSwitch::setChecked(bool checked) {
  if (m_checked == checked)
    return;
  m_checked = checked;
  update();
  emit toggled(m_checked);
}

void ToggleSwitch::paintEvent(QPaintEvent*) {
  QPainter p(this);
  p.setRenderHint(QPainter::Antialiasing, true);

  // ── Track ───────────────────────────────────────────────────────────
  p.setPen(Qt::NoPen);
  p.setBrush(QColor(m_checked ? Theme::Color::accentBlue : Theme::Color::borderSubtle));
  p.drawRoundedRect(rect(), height() / 2.0, height() / 2.0);

  // ── Knob ────────────────────────────────────────────────────────────
  const int knobSize = height() - 4;
  const int knobX = m_checked ? width() - knobSize - 2 : 2;
  p.setBrush(QColor("#FFFFFF"));
  p.drawEllipse(QRect(knobX, 2, knobSize, knobSize));
}

void ToggleSwitch::mouseReleaseEvent(QMouseEvent* e) {
  if (e->button() == Qt::LeftButton && rect().contains(e->pos()))
    setChecked(!m_checked);
  QWidget::mouseReleaseEvent(e);
}

// ---------------------------------------------------------------------------
// ToggleRow
// ---------------------------------------------------------------------------
ToggleRow::ToggleRow(const QString& label, const QString& description, QWidget* parent)
    : QFrame(parent) {
  setObjectName("OdyToggleRow");
  setAttribute(Qt::WA_StyledBackground, true);
  setStyleSheet("QFrame#OdyToggleRow { background: transparent; }");

  auto* h = new QHBoxLayout(this);
  h->setContentsMargins(0, 10, 0, 10);
  h->setSpacing(16);

  auto* textCol = new QVBoxLayout();
  textCol->setContentsMargins(0, 0, 0, 0);
  textCol->setSpacing(2);

  m_label = new QLabel(label, this);
  m_label->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                             .arg(Theme::Color::textPrimary)
                             .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi)));
  textCol->addWidget(m_label);

  m_description = new QLabel(description, this);
  m_description->setWordWrap(true);
  m_description->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                                   .arg(Theme::Color::textSecondary)
                                   .arg(Theme::Type::qss(Theme::Type::Caption)));
  textCol->addWidget(m_description);

  h->addLayout(textCol, 1);

  m_switch = new ToggleSwitch(this);
  h->addWidget(m_switch, 0, Qt::AlignTop);

  connect(m_switch, &ToggleSwitch::toggled, this, &ToggleRow::toggled);
}

bool ToggleRow::isChecked() const {
  return m_switch->isChecked();
}
void ToggleRow::setChecked(bool checked) {
  m_switch->setChecked(checked);
}
