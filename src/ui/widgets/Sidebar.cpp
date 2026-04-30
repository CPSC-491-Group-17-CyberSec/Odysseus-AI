// ============================================================================
// Sidebar.cpp
// ============================================================================

#include "Sidebar.h"

#include <QButtonGroup>
#include <QFont>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

#include "../theme/DashboardTheme.h"

namespace {

// One stylesheet for all nav buttons. We use the :checked pseudo-state so
// QButtonGroup's exclusive selection drives the active highlight without
// any imperative styling.
QString navButtonQss() {
  return QString(
             "QPushButton {"
             "  background-color: transparent;"
             "  color: %1;"
             "  text-align: left;"
             "  padding: 10px 14px;"
             "  border: none;"
             "  border-radius: %5px;"
             "  font-size: 13px;"
             "  font-weight: 500;"
             "}"
             "QPushButton:hover {"
             "  background-color: %2;"
             "  color: %3;"
             "}"
             "QPushButton:checked {"
             "  background-color: %4;"
             "  color: white;"
             "  font-weight: 600;"
             "}")
      .arg(Theme::Color::textSecondary)     // %1
      .arg(Theme::Color::bgCard)            // %2
      .arg(Theme::Color::textPrimary)       // %3
      .arg(Theme::Color::accentBlue)        // %4
      .arg(Theme::Size::sidebarBtnRadius);  // %5
}

}  // namespace

Sidebar::Sidebar(QWidget* parent)
    : QWidget(parent) {
  setObjectName("OdySidebar");
  setFixedWidth(Theme::Size::sidebarWidth);
  setAttribute(Qt::WA_StyledBackground, true);
  setStyleSheet(
      QString("QWidget#OdySidebar { background-color: %1; }").arg(Theme::Color::bgSidebar));

  auto* layout = new QVBoxLayout(this);
  layout->setContentsMargins(16, 24, 16, 16);
  layout->setSpacing(4);

  // ── Brand ────────────────────────────────────────────────────────────
  auto* brand = new QLabel("ODYSSEUS-AI", this);
  brand->setStyleSheet(QString("QLabel { color: %1; font-size: 16px; font-weight: 700;"
                               " letter-spacing: 1px; padding: 0 4px; }")
                           .arg(Theme::Color::accentBlue));
  layout->addWidget(brand);

  auto* tagline = new QLabel("AI-Powered Cybersecurity", this);
  tagline->setStyleSheet(QString("QLabel { color: %1; font-size: 10px; padding: 0 4px 18px 4px; }")
                             .arg(Theme::Color::textMuted));
  layout->addWidget(tagline);

  // ── Buttons container ────────────────────────────────────────────────
  m_buttonsLayout = new QVBoxLayout();
  m_buttonsLayout->setContentsMargins(0, 0, 0, 0);
  m_buttonsLayout->setSpacing(2);
  layout->addLayout(m_buttonsLayout);

  layout->addStretch(1);

  // ── Footer ───────────────────────────────────────────────────────────
  m_footer = new QLabel("", this);
  m_footer->setAlignment(Qt::AlignCenter);
  m_footer->setStyleSheet(
      QString("QLabel { color: %1; font-size: 10px; padding: 4px; }").arg(Theme::Color::textMuted));
  layout->addWidget(m_footer);

  m_group = new QButtonGroup(this);
  m_group->setExclusive(true);
}

int Sidebar::addItem(const QString& label, const QString& glyph) {
  auto* btn = new QPushButton(this);
  // Glyph + label, padded so labels align even with variable-width glyphs.
  btn->setText(QString("  %1   %2").arg(glyph, label));
  btn->setCheckable(true);
  btn->setCursor(Qt::PointingHandCursor);
  btn->setStyleSheet(navButtonQss());

  QFont f = btn->font();
  f.setPointSizeF(f.pointSizeF() + 0.5);
  btn->setFont(f);

  const int idx = m_buttons.size();
  m_buttons.append(btn);
  m_group->addButton(btn, idx);
  m_buttonsLayout->addWidget(btn);

  connect(btn, &QPushButton::clicked, this, &Sidebar::onButtonClicked);

  if (idx == 0)
    btn->setChecked(true);
  return idx;
}

void Sidebar::setActive(int index) {
  if (index < 0 || index >= m_buttons.size())
    return;
  QPushButton* btn = m_buttons[index];
  QSignalBlocker block(btn);
  btn->setChecked(true);
}

void Sidebar::setFooterText(const QString& text) {
  if (m_footer)
    m_footer->setText(text);
}

void Sidebar::onButtonClicked() {
  if (auto* sender = qobject_cast<QPushButton*>(QObject::sender())) {
    const int id = m_group->id(sender);
    if (id >= 0)
      emit pageRequested(id);
  }
}
