// ============================================================================
// DetailSection.cpp
// ============================================================================

#include "DetailSection.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QVBoxLayout>

#include "../theme/DashboardTheme.h"

DetailSection::DetailSection(const QString& title, const QString& accentHex, QWidget* parent)
    : QFrame(parent) {
  m_accentHex = accentHex.isEmpty() ? QString(Theme::Color::accentBlue) : accentHex;

  // Modern detail section — no nested boxes, no left border bar.
  // Only visual accent is a small colored dot before the title.
  setObjectName("OdyDetailSection");
  setAttribute(Qt::WA_StyledBackground, true);
  setStyleSheet("QFrame#OdyDetailSection { background: transparent; border: none; }");

  auto* v = new QVBoxLayout(this);
  v->setContentsMargins(0, 0, 0, 0);
  v->setSpacing(10);

  // ── Title row: small colored dot + title ──────────────────────────
  auto* titleRow = new QHBoxLayout();
  titleRow->setContentsMargins(0, 0, 0, 0);
  titleRow->setSpacing(10);

  auto* dot = new QLabel(this);
  dot->setFixedSize(6, 6);
  dot->setStyleSheet(
      QString("QLabel { background-color: %1; border-radius: 3px; }").arg(m_accentHex));
  titleRow->addWidget(dot, 0, Qt::AlignVCenter);

  m_titleLabel = new QLabel(title, this);
  m_titleLabel->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                                  .arg(Theme::Color::textPrimary)
                                  .arg(Theme::Type::qss(Theme::Type::H3, Theme::Type::WeightSemi)));
  titleRow->addWidget(m_titleLabel, 1);

  v->addLayout(titleRow);

  m_body = new QVBoxLayout();
  m_body->setContentsMargins(16, 0, 0, 0);  // align body under the title
  m_body->setSpacing(6);
  v->addLayout(m_body);
}

void DetailSection::clear() {
  while (QLayoutItem* item = m_body->takeAt(0)) {
    if (QWidget* w = item->widget())
      w->deleteLater();
    delete item;
  }
}

void DetailSection::setBody(const QString& bodyText) {
  clear();
  auto* lab = new QLabel(bodyText, this);
  lab->setWordWrap(true);
  lab->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent;"
                             " line-height: 1.5; }")
                         .arg(Theme::Color::textPrimary)
                         .arg(Theme::Type::qss(Theme::Type::Body)));
  lab->setTextInteractionFlags(Qt::TextSelectableByMouse);
  m_body->addWidget(lab);
}

void DetailSection::setBullets(const QStringList& bullets) {
  clear();
  if (bullets.isEmpty()) {
    auto* lab = new QLabel("(none)", this);
    lab->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent;"
                               " font-style: italic; }")
                           .arg(Theme::Color::textMuted)
                           .arg(Theme::Type::qss(Theme::Type::Body)));
    m_body->addWidget(lab);
    return;
  }
  for (const QString& b : bullets) {
    auto* lab = new QLabel(QString::fromUtf8("\xE2\x80\xA2 ") + b, this);
    lab->setWordWrap(true);
    lab->setTextInteractionFlags(Qt::TextSelectableByMouse);
    lab->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent;"
                               " line-height: 1.45; }")
                           .arg(Theme::Color::textPrimary)
                           .arg(Theme::Type::qss(Theme::Type::Body)));
    m_body->addWidget(lab);
  }
}
