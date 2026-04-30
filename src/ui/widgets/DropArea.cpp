// ============================================================================
// DropArea.cpp
// ============================================================================

#include "DropArea.h"

#include <QDragEnterEvent>
#include <QDropEvent>
#include <QLabel>
#include <QMimeData>
#include <QUrl>
#include <QVBoxLayout>

#include "../theme/DashboardTheme.h"

DropArea::DropArea(QWidget* parent)
    : QFrame(parent) {
  setObjectName("OdyDropArea");
  setAttribute(Qt::WA_StyledBackground, true);
  setAcceptDrops(true);
  setMinimumHeight(180);

  auto* v = new QVBoxLayout(this);
  v->setContentsMargins(20, 28, 20, 28);
  v->setSpacing(12);
  v->setAlignment(Qt::AlignCenter);

  // Folder glyph in an accent-blue tinted square — matches mockup.
  m_iconLabel = new QLabel(QString::fromUtf8("\xE2\x96\xA4"), this);  // ▤
  m_iconLabel->setAlignment(Qt::AlignCenter);
  m_iconLabel->setFixedSize(56, 56);
  m_iconLabel->setStyleSheet(QString("QLabel { color: %1; background-color: %2;"
                                     " border-radius: 12px; font-size: 24px; }")
                                 .arg(Theme::Color::accentBlue, Theme::Color::accentBlueSoft));
  v->addWidget(m_iconLabel, 0, Qt::AlignCenter);

  m_titleLabel = new QLabel("Drag and drop files or folders here", this);
  m_titleLabel->setAlignment(Qt::AlignCenter);
  m_titleLabel->setStyleSheet(
      QString("QLabel { color: %1; %2 background: transparent; }")
          .arg(Theme::Color::textPrimary)
          .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi)));
  v->addWidget(m_titleLabel);

  m_subLabel = new QLabel("or click the button below to browse", this);
  m_subLabel->setAlignment(Qt::AlignCenter);
  m_subLabel->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                                .arg(Theme::Color::textSecondary)
                                .arg(Theme::Type::qss(Theme::Type::Caption)));
  v->addWidget(m_subLabel);

  applyStyle();
}

void DropArea::dragEnterEvent(QDragEnterEvent* e) {
  if (e->mimeData()->hasUrls()) {
    m_hovered = true;
    applyStyle();
    e->acceptProposedAction();
  }
}

void DropArea::dragLeaveEvent(QDragLeaveEvent* /*e*/) {
  m_hovered = false;
  applyStyle();
}

void DropArea::dropEvent(QDropEvent* e) {
  m_hovered = false;
  applyStyle();

  QStringList paths;
  for (const QUrl& u : e->mimeData()->urls()) {
    if (u.isLocalFile())
      paths.append(u.toLocalFile());
  }
  if (!paths.isEmpty())
    emit filesDropped(paths);
  e->acceptProposedAction();
}

void DropArea::applyStyle() {
  // Dashed border tightens to solid + accent on hover. The bg gets a
  // soft accent tint while hovered so the user gets clear "you can drop
  // here" feedback even without any animation.
  const QString border = m_hovered ? Theme::Color::accentBlue : Theme::Color::borderSubtle;
  const QString bg = m_hovered ? Theme::Color::accentBlueSoft : Theme::Color::bgSecondary;
  const char* style = m_hovered ? "solid" : "dashed";

  setStyleSheet(QString("QFrame#OdyDropArea {"
                        "  background-color: %1;"
                        "  border: 2px %2 %3;"
                        "  border-radius: 12px;"
                        "}")
                    .arg(bg)
                    .arg(style)
                    .arg(border));
}
