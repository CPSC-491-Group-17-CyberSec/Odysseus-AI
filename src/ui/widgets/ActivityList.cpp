// ============================================================================
// ActivityList.cpp
// ============================================================================

#include "ActivityList.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QListWidgetItem>
#include <QPainter>
#include <QPushButton>
#include <QVBoxLayout>

#include "../theme/DashboardTheme.h"

namespace {

const char* glyphFor(ActivityList::Tone t) {
  switch (t) {
    case ActivityList::Critical:
      return "\xE2\x9A\xA0";  // ⚠ threat detected
    case ActivityList::Warning:
      return "\xE2\x9A\xA0";  // ⚠ suspicious
    case ActivityList::Info:
      return "\xE2\x96\xB6";  // ▶ scan completed
    case ActivityList::Success:
      return "\xE2\x9C\x93";  // ✓ all clear
    case ActivityList::System:
      return "\xE2\x97\x8E";  // ◎ system event
  }
  return "?";
}

const char* colorFor(ActivityList::Tone t) {
  switch (t) {
    case ActivityList::Critical:
      return Theme::Color::severityCritical;
    case ActivityList::Warning:
      return Theme::Color::severityMedium;
    case ActivityList::Info:
      return Theme::Color::accentBlue;
    case ActivityList::Success:
      return Theme::Color::severitySafe;
    case ActivityList::System:
      return "#A78BFA";  // soft purple
  }
  return Theme::Color::textPrimary;
}

QString relativeTime(const QDateTime& when) {
  if (!when.isValid())
    return "—";
  const qint64 secs = when.secsTo(QDateTime::currentDateTime());
  if (secs < 60)
    return QString("%1 sec ago").arg(secs);
  if (secs < 60 * 60)
    return QString("%1 min ago").arg(secs / 60);
  if (secs < 60 * 60 * 24)
    return QString("%1 hour ago").arg(secs / 3600);
  return when.toString("MMM d");
}

/// Truncate a long path / subtitle so it fits one row without wrapping.
/// We keep the leaf (right-most segment) since that's the part that
/// uniquely identifies the file — collapse the front with an ellipsis.
QString truncateForRow(const QString& s, int maxChars = 56) {
  if (s.length() <= maxChars)
    return s;
  return QString::fromUtf8("\xE2\x80\xA6")  // …
         + s.right(maxChars - 1);
}

}  // namespace

ActivityList::ActivityList(QWidget* parent)
    : QFrame(parent) {
  setObjectName("OdyActivityList");
  setAttribute(Qt::WA_StyledBackground, true);
  setStyleSheet(QString("QFrame#OdyActivityList {"
                        "  background-color: %1;"
                        "  border: 1px solid %2;"
                        "  border-radius: %3px;"
                        "}")
                    .arg(Theme::Color::bgCard, Theme::Color::borderSubtle)
                    .arg(Theme::Size::cardRadius));

  auto* v = new QVBoxLayout(this);
  v->setContentsMargins(20, 16, 20, 16);
  v->setSpacing(12);

  // Header row
  auto* headerRow = new QHBoxLayout();
  auto* title = new QLabel("Recent Activity", this);
  title->setStyleSheet(
      QString("color: %1; font-size: 16px; font-weight: 700;").arg(Theme::Color::textPrimary));
  headerRow->addWidget(title);
  headerRow->addStretch(1);

  auto* viewAll = new QPushButton("View All", this);
  viewAll->setCursor(Qt::PointingHandCursor);
  viewAll->setFlat(true);
  viewAll->setStyleSheet(
      QString("QPushButton { background: transparent; color: %1; font-size: 12px;"
              " font-weight: 600; padding: 4px 8px; border: none; }"
              "QPushButton:hover { color: %2; }")
          .arg(Theme::Color::accentBlue, Theme::Color::accentBlueHover));
  connect(viewAll, &QPushButton::clicked, this, &ActivityList::viewAllClicked);
  headerRow->addWidget(viewAll);
  v->addLayout(headerRow);

  // List
  m_list = new QListWidget(this);
  m_list->setStyleSheet(
      QString("QListWidget {"
              "  background: transparent; border: none; padding: 0;"
              "}"
              "QListWidget::item {"
              "  border-bottom: 1px solid %1;"
              "  padding: 8px 0;"
              "}"
              "QListWidget::item:hover { background-color: %2; }"
              "QListWidget::item:selected { background-color: %3; color: white; }")
          .arg(
              Theme::Color::borderSubtle, Theme::Color::bgCardHover, Theme::Color::accentBlueSoft));
  m_list->setFrameShape(QFrame::NoFrame);
  m_list->setSelectionMode(QAbstractItemView::SingleSelection);
  v->addWidget(m_list, 1);
}

void ActivityList::setEntries(const QVector<Entry>& entries) {
  m_list->clear();
  if (entries.isEmpty()) {
    auto* item = new QListWidgetItem("No recent activity yet.");
    item->setForeground(QColor(Theme::Color::textMuted));
    item->setFlags(Qt::ItemIsEnabled);
    m_list->addItem(item);
    return;
  }

  for (const auto& e : entries) {
    auto* row = new QWidget();
    // Whole-row tooltip = title + full subtitle so the user can hover
    // anywhere to see the un-truncated information.
    QString tip = e.title;
    if (!e.subtitle.isEmpty())
      tip += "\n" + e.subtitle;
    row->setToolTip(tip);
    auto* h = new QHBoxLayout(row);
    // Stabilization D — bumped padding for breathing room
    h->setContentsMargins(4, 8, 4, 8);
    h->setSpacing(14);

    // Tone icon — bigger, in a soft tinted square so it reads at a
    // glance even in peripheral vision.
    auto* iconWrap = new QFrame(row);
    iconWrap->setFixedSize(34, 34);
    iconWrap->setStyleSheet(QString("QFrame { background-color: %1; border-radius: 8px; }")
                                .arg(Theme::Color::bgPrimary));
    auto* iconWrapLayout = new QVBoxLayout(iconWrap);
    iconWrapLayout->setContentsMargins(0, 0, 0, 0);
    iconWrapLayout->setAlignment(Qt::AlignCenter);
    auto* icon = new QLabel(QString::fromUtf8(glyphFor(e.tone)), iconWrap);
    icon->setAlignment(Qt::AlignCenter);
    icon->setStyleSheet(QString("QLabel { color: %1; font-size: 16px; font-weight: 700;"
                                " background: transparent; }")
                            .arg(colorFor(e.tone)));
    iconWrapLayout->addWidget(icon);
    h->addWidget(iconWrap);

    auto* textCol = new QVBoxLayout();
    textCol->setContentsMargins(0, 0, 0, 0);
    textCol->setSpacing(3);

    // Title is ALWAYS off-white for readability. Severity is encoded
    // by the icon-square color, not by the title color (the previous
    // approach made critical-red titles readable but yellow / blue
    // titles dim against the dark background).
    auto* tl = new QLabel(e.title, row);
    tl->setStyleSheet(QString("QLabel { color: %1; font-size: 13px; font-weight: 600;"
                              " background: transparent; }")
                          .arg(Theme::Color::textPrimary));
    tl->setTextInteractionFlags(Qt::TextSelectableByMouse);
    textCol->addWidget(tl);

    if (!e.subtitle.isEmpty()) {
      // Polish.3 — truncate long paths so the row never wraps; the
      // full path is preserved on hover via tooltip.
      const QString shown = truncateForRow(e.subtitle);
      auto* sl = new QLabel(shown, row);
      sl->setStyleSheet(QString("QLabel { color: %1; font-size: 11px;"
                                " background: transparent; }")
                            .arg(Theme::Color::textSecondary));
      sl->setTextInteractionFlags(Qt::TextSelectableByMouse);
      sl->setWordWrap(false);
      sl->setToolTip(e.subtitle);
      textCol->addWidget(sl);
    }
    h->addLayout(textCol, 1);

    auto* ts = new QLabel(relativeTime(e.when), row);
    ts->setStyleSheet(QString("QLabel { color: %1; font-size: 11px; font-weight: 500;"
                              " background: transparent; }")
                          .arg(Theme::Color::textSecondary));
    h->addWidget(ts, 0, Qt::AlignTop);

    auto* item = new QListWidgetItem(m_list);
    // Size hint follows the row's natural size + a little padding so the
    // hover highlight feels generous.
    QSize hint = row->sizeHint();
    hint.setHeight(hint.height() + 6);
    item->setSizeHint(hint);
    m_list->setItemWidget(item, row);
  }
}

void ActivityList::clearEntries() {
  m_list->clear();
}
