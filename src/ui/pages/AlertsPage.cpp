// ============================================================================
// AlertsPage.cpp
// ============================================================================

#include "AlertsPage.h"

#include <QDateTime>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QTimer>
#include <QVBoxLayout>

#include "../theme/DashboardTheme.h"
#include "../widgets/AlertDetailPanel.h"
#include "../widgets/AlertRow.h"
#include "../widgets/FilterBar.h"
#include "../widgets/StatCard.h"

namespace {

// ── Grouping window: alerts within this many seconds, sharing the same
//     (category, sourcePath), are folded into one display row.           ──
constexpr int kGroupWindowSecs = 60;

// ── If row count exceeds this we'd switch to a virtualized list. For
//     now, EDR-Lite typical output stays well under this threshold.       ──
constexpr int kVirtualizeThreshold = 200;

QString relTime(const QDateTime& when) {
  if (!when.isValid())
    return "—";
  const qint64 secs = when.secsTo(QDateTime::currentDateTime());
  if (secs < 5)
    return "just now";
  if (secs < 60)
    return QString("%1s ago").arg(secs);
  if (secs < 60 * 60)
    return QString("%1m ago").arg(secs / 60);
  if (secs < 60 * 60 * 24)
    return QString("%1h ago").arg(secs / 3600);
  return when.toString("MMM d");
}

}  // namespace

// ============================================================================
//  Construction
// ============================================================================
AlertsPage::AlertsPage(QWidget* parent)
    : QWidget(parent) {
  setStyleSheet(QString("background-color: %1;").arg(Theme::Color::bgPrimary));
  buildUi();
  rebuildList();
  refreshKpis();
  refreshTimelineLabel();
}

void AlertsPage::buildUi() {
  auto* outer = new QVBoxLayout(this);
  outer->setContentsMargins(0, 0, 0, 0);
  outer->setSpacing(0);

  auto* scroll = new QScrollArea(this);
  scroll->setWidgetResizable(true);
  scroll->setFrameShape(QFrame::NoFrame);
  scroll->setStyleSheet("background: transparent;");
  outer->addWidget(scroll);

  auto* content = new QWidget();
  content->setStyleSheet("background: transparent;");
  auto* main = new QVBoxLayout(content);
  main->setContentsMargins(32, 28, 32, 28);
  main->setSpacing(20);

  // ── Header ──────────────────────────────────────────────────────────
  auto* titleCol = new QVBoxLayout();
  titleCol->setSpacing(2);
  m_title = new QLabel("Alerts", content);
  m_title->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                             .arg(Theme::Color::textPrimary)
                             .arg(Theme::Type::qss(Theme::Type::Display, Theme::Type::WeightBold)));
  titleCol->addWidget(m_title);

  m_subtitle = new QLabel("EDR-Lite alerts from continuous system monitoring", content);
  m_subtitle->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                                .arg(Theme::Color::textSecondary)
                                .arg(Theme::Type::qss(Theme::Type::Body)));
  titleCol->addWidget(m_subtitle);
  main->addLayout(titleCol);

  // ── Timeline strip ──────────────────────────────────────────────────
  m_timeline = new QFrame(content);
  m_timeline->setObjectName("OdyAlertTimeline");
  m_timeline->setAttribute(Qt::WA_StyledBackground, true);
  m_timeline->setStyleSheet(QString("QFrame#OdyAlertTimeline {"
                                    "  background-color: %1; border: 1px solid %2;"
                                    "  border-radius: 10px;"
                                    "}")
                                .arg(Theme::Color::bgCard, Theme::Color::borderSubtle));

  auto* tl = new QHBoxLayout(m_timeline);
  tl->setContentsMargins(14, 10, 14, 10);
  tl->setSpacing(10);

  m_timelineDot = new QLabel(m_timeline);
  m_timelineDot->setFixedSize(8, 8);
  m_timelineDot->setStyleSheet(
      QString("QLabel { background-color: %1; border-radius: 4px; }").arg(Theme::Color::textMuted));
  tl->addWidget(m_timelineDot, 0, Qt::AlignVCenter);

  m_timelineText = new QLabel("EDR-Lite is currently OFF.", m_timeline);
  m_timelineText->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                                    .arg(Theme::Color::textSecondary)
                                    .arg(Theme::Type::qss(Theme::Type::Body)));
  tl->addWidget(m_timelineText, 1, Qt::AlignVCenter);

  main->addWidget(m_timeline);

  // Refresh the relative time every 10s so "5s ago" doesn't go stale.
  m_timelineTick = new QTimer(this);
  m_timelineTick->setInterval(10 * 1000);
  connect(m_timelineTick, &QTimer::timeout, this, &AlertsPage::onTimelineRefresh);
  m_timelineTick->start();

  // ── KPI strip ───────────────────────────────────────────────────────
  auto* kpis = new QHBoxLayout();
  kpis->setSpacing(16);

  m_kpiTotal = new StatCard(content);
  m_kpiTotal->setTone(StatCard::Info);
  m_kpiTotal->setTitle("TOTAL ALERTS");
  m_kpiTotal->setValue("0");
  m_kpiTotal->setSubtitle("Since app start");
  m_kpiTotal->setIcon("");
  kpis->addWidget(m_kpiTotal, 1);

  m_kpiCritical = new StatCard(content);
  m_kpiCritical->setTone(StatCard::Critical);
  m_kpiCritical->setTitle("CRITICAL");
  m_kpiCritical->setValue("0");
  m_kpiCritical->setSubtitle("Highest severity");
  m_kpiCritical->setIcon("");
  kpis->addWidget(m_kpiCritical, 1);

  m_kpiHigh = new StatCard(content);
  m_kpiHigh->setTone(StatCard::Warning);
  m_kpiHigh->setTitle("HIGH");
  m_kpiHigh->setValue("0");
  m_kpiHigh->setSubtitle("Needs attention");
  m_kpiHigh->setIcon("");
  kpis->addWidget(m_kpiHigh, 1);

  m_kpiRecent = new StatCard(content);
  m_kpiRecent->setTone(StatCard::Safe);
  m_kpiRecent->setTitle("LAST HOUR");
  m_kpiRecent->setValue("0");
  m_kpiRecent->setSubtitle("Recent activity");
  m_kpiRecent->setIcon("");
  kpis->addWidget(m_kpiRecent, 1);

  main->addLayout(kpis);

  // ── Filter bar ──────────────────────────────────────────────────────
  m_filterBar = new FilterBar(content);
  connect(m_filterBar, &FilterBar::filtersChanged, this, &AlertsPage::onFiltersChanged);
  main->addWidget(m_filterBar);

  // ── List + detail split ─────────────────────────────────────────────
  auto* split = new QHBoxLayout();
  split->setSpacing(20);

  // ── Left: scrollable list of AlertRow widgets ──────────────────────
  m_listScroll = new QScrollArea(content);
  m_listScroll->setWidgetResizable(true);
  m_listScroll->setFrameShape(QFrame::NoFrame);
  m_listScroll->setStyleSheet("background: transparent;");

  m_listHost = new QWidget();
  m_listHost->setStyleSheet("background: transparent;");
  m_listLayout = new QVBoxLayout(m_listHost);
  m_listLayout->setContentsMargins(0, 0, 0, 0);
  m_listLayout->setSpacing(8);

  m_emptyState = new QLabel(
      "No alerts yet. Enable EDR-Lite Monitoring (Beta) in Settings to "
      "start watching for system changes.",
      m_listHost);
  m_emptyState->setAlignment(Qt::AlignCenter);
  m_emptyState->setWordWrap(true);
  m_emptyState->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent;"
                                      " padding: 60px 40px; }")
                                  .arg(Theme::Color::textMuted)
                                  .arg(Theme::Type::qss(Theme::Type::Body)));
  m_listLayout->addWidget(m_emptyState);

  m_loadingState = new QLabel("Checking system for changes…", m_listHost);
  m_loadingState->setAlignment(Qt::AlignCenter);
  m_loadingState->setWordWrap(true);
  m_loadingState->setStyleSheet(
      QString("QLabel { color: %1; %2 background: transparent;"
              " padding: 60px 40px; }")
          .arg(Theme::Color::textMuted)
          .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi)));
  m_loadingState->setVisible(false);
  m_listLayout->addWidget(m_loadingState);

  m_listLayout->addStretch(1);
  m_listScroll->setWidget(m_listHost);
  split->addWidget(m_listScroll, 5);

  // ── Right: detail panel ────────────────────────────────────────────
  m_detail = new AlertDetailPanel(content);
  connect(
      m_detail,
      &AlertDetailPanel::openLocationRequested,
      this,
      &AlertsPage::onOpenLocationRequested);
  split->addWidget(m_detail, 0);

  main->addLayout(split, 1);

  scroll->setWidget(content);
}

// ============================================================================
//  Public API
// ============================================================================
void AlertsPage::setAlerts(const QVector<EDR::Alert>& alerts) {
  m_alerts = alerts;
  m_selectedRow = -1;
  m_selectedAlertId.clear();
  rebuildList();
  refreshKpis();
}

void AlertsPage::appendAlert(const EDR::Alert& alert) {
  // Most-recent first
  m_alerts.prepend(alert);
  rebuildList();
  refreshKpis();
}

void AlertsPage::markAlertResolved(const EDR::Alert& alert) {
  // The MonitoringService updated its own m_alerts in place too, but
  // we keep our own copy for UI snapshot independence — find by id
  // and patch.
  for (EDR::Alert& a : m_alerts) {
    if (a.id == alert.id) {
      a.status = EDR::AlertStatus::Resolved;
      a.resolvedAt = alert.resolvedAt;
      a.lastSeen = alert.lastSeen;
      a.ticksSeen = alert.ticksSeen;
      a.occurrenceCount = alert.occurrenceCount;
      break;
    }
  }
  rebuildList();
  refreshKpis();
}

void AlertsPage::updateAlert(const EDR::Alert& alert) {
  bool changed = false;
  for (EDR::Alert& a : m_alerts) {
    if (a.id == alert.id) {
      a.lastSeen = alert.lastSeen;
      a.ticksSeen = alert.ticksSeen;
      a.occurrenceCount = alert.occurrenceCount;
      changed = true;
      break;
    }
  }
  if (changed) {
    rebuildList();
    refreshKpis();
  }
}

void AlertsPage::clear() {
  m_alerts.clear();
  m_selectedRow = -1;
  m_selectedAlertId.clear();
  if (m_detail)
    m_detail->clear();
  rebuildList();
  refreshKpis();
}

void AlertsPage::setLastTick(const QDateTime& when, int alertsThisTick) {
  m_lastTickAt = when;
  m_lastTickNewAlerts = alertsThisTick;
  m_haveFirstTick = true;
  refreshTimelineLabel();
  // Loading hint becomes irrelevant once we have a tick.
  if (m_loadingState)
    m_loadingState->setVisible(false);
}

void AlertsPage::setEdrRunning(bool running) {
  m_edrRunning = running;
  if (!running) {
    m_haveFirstTick = false;
    m_lastTickAt = QDateTime();
    m_lastTickNewAlerts = 0;
  }
  refreshTimelineLabel();
  rebuildList();  // empty/loading state may flip
}

// ============================================================================
//  Filtering + grouping
// ============================================================================
bool AlertsPage::passesFilters(const EDR::Alert& a) const {
  if (!m_filterBar)
    return true;

  const int sevSel = m_filterBar->selectedSeverity();
  const QString cat = m_filterBar->selectedCategory();
  const QString q = m_filterBar->searchText();

  if (sevSel >= 0 && static_cast<int>(a.severity) != sevSel)
    return false;
  if (!cat.isEmpty() && a.category != cat)
    return false;
  if (!q.isEmpty()) {
    const QString needle = q.toLower();
    if (!a.title.toLower().contains(needle) && !a.sourcePath.toLower().contains(needle) &&
        !a.category.toLower().contains(needle) && !a.description.toLower().contains(needle)) {
      return false;
    }
  }
  return true;
}

QVector<AlertsPage::Group> AlertsPage::groupAndFilter() const {
  // Walk the alerts (most-recent-first). For each one that passes
  // filters, fold into the most-recent existing group with matching
  // (category, sourcePath) whose representative timestamp is within
  // kGroupWindowSecs. Otherwise start a new group.
  QVector<Group> out;
  out.reserve(m_alerts.size());

  for (int i = 0; i < m_alerts.size(); ++i) {
    const EDR::Alert& a = m_alerts[i];
    if (!passesFilters(a))
      continue;

    bool merged = false;
    for (Group& g : out) {
      if (g.representative.category == a.category && g.representative.sourcePath == a.sourcePath) {
        // Time check: if the group's representative is within
        // kGroupWindowSecs of this alert, merge.
        const QDateTime ref = g.representative.timestamp.isValid() ? g.representative.timestamp
                                                                   : g.representative.lastSeen;
        const QDateTime cur = a.timestamp.isValid() ? a.timestamp : a.lastSeen;
        if (ref.isValid() && cur.isValid() && qAbs(ref.secsTo(cur)) <= kGroupWindowSecs) {
          g.occurrences++;
          g.sourceIndices.append(i);
          // Bump representative.lastSeen / firstSeen across the group
          if (!g.representative.lastSeen.isValid() || cur > g.representative.lastSeen) {
            g.representative.lastSeen = cur;
          }
          if (!g.representative.firstSeen.isValid() || cur < g.representative.firstSeen) {
            g.representative.firstSeen = cur;
          }
          merged = true;
          break;
        }
      }
    }
    if (!merged) {
      Group g;
      g.representative = a;
      // Initialize firstSeen/lastSeen from the alert's timestamp
      // if SnapshotDiff didn't set them.
      if (!g.representative.firstSeen.isValid())
        g.representative.firstSeen = a.timestamp;
      if (!g.representative.lastSeen.isValid())
        g.representative.lastSeen = a.timestamp;
      g.sourceIndices.append(i);
      out.append(g);
    }
  }
  return out;
}

// ============================================================================
//  Row rendering
// ============================================================================
void AlertsPage::rebuildList() {
  // Tear down existing AlertRow widgets (cheap; <200 typically).
  for (AlertRow* r : m_rows) {
    m_listLayout->removeWidget(r);
    r->deleteLater();
  }
  m_rows.clear();

  // Compute groups
  m_currentGroups = groupAndFilter();

  // Decide which placeholder (if any) to show
  const bool noFilteredResults = m_currentGroups.isEmpty();
  const bool haveAnyAlerts = !m_alerts.isEmpty();

  if (noFilteredResults) {
    if (m_edrRunning && !m_haveFirstTick) {
      // EDR is running but hasn't completed its first tick yet
      m_loadingState->setVisible(true);
      m_emptyState->setVisible(false);
    } else if (haveAnyAlerts) {
      // We have alerts, but the current filters hide them all
      m_emptyState->setText(
          "No alerts match the current filters.\n"
          "Try widening the severity chip or clearing the search.");
      m_emptyState->setVisible(true);
      m_loadingState->setVisible(false);
    } else if (m_edrRunning) {
      // ── ITEM 4 — clarify alert source ──
      // Demo viewers were confused when the Dashboard showed
      // "Critical threats detected" (from file scans) while this page
      // read 0 alerts. The text now spells out the source split.
      m_emptyState->setText(
          "No alerts so far. Your system looks good.\n\n"
          "Note: Alerts on this page come from real-time monitoring "
          "(EDR-Lite) — process / persistence / integrity / kernel-"
          "extension changes. They are NOT file-scan results. To see "
          "scanned-file findings, switch to the Results page.");
      m_emptyState->setVisible(true);
      m_loadingState->setVisible(false);
    } else {
      // EDR off → re-emphasise that file-scan findings live on the
      // Results page, not here, so the user doesn't expect them.
      m_emptyState->setText(
          "No alerts yet. Enable EDR-Lite Monitoring (Beta) in "
          "Settings to start watching for system changes.\n\n"
          "Note: Alerts on this page come from real-time monitoring "
          "only — file-scan findings appear on the Results page.");
      m_emptyState->setVisible(true);
      m_loadingState->setVisible(false);
    }
    return;
  }

  m_emptyState->setVisible(false);
  m_loadingState->setVisible(false);

  // Build rows. Insert before the trailing stretch so cards stack at top.
  const int stretchIdx = m_listLayout->count() - 1;
  for (int i = 0; i < m_currentGroups.size(); ++i) {
    const Group& g = m_currentGroups[i];
    auto* row = new AlertRow(m_listHost);
    row->setAlert(
        g.representative,
        i,
        g.occurrences,
        /*isGroupHeader*/ g.occurrences > 1);
    row->setZebra(i % 2 == 1);
    connect(row, &AlertRow::clicked, this, &AlertsPage::onRowClicked);
    m_listLayout->insertWidget(stretchIdx + i, row);
    m_rows.append(row);

    if (i == kVirtualizeThreshold) {
      // Cap to first N rows; beyond this we'd switch to a model/view.
      // (Keep going past the limit with a visible warning instead of
      // silently truncating, so the user knows.)
      auto* warn = new QLabel(
          QString("(showing first %1 of %2 alerts — refine filters to "
                  "narrow down)")
              .arg(kVirtualizeThreshold)
              .arg(m_currentGroups.size()),
          m_listHost);
      warn->setAlignment(Qt::AlignCenter);
      warn->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent;"
                                  " padding: 16px; font-style: italic; }")
                              .arg(Theme::Color::textMuted)
                              .arg(Theme::Type::qss(Theme::Type::Caption)));
      m_listLayout->insertWidget(stretchIdx + i + 1, warn);
      break;
    }
  }

  // Restore previous selection by alert ID — survives re-grouping when
  // a new alert is prepended (which would shift all group indices).
  if (!m_selectedAlertId.isEmpty()) {
    int found = -1;
    for (int i = 0; i < m_currentGroups.size(); ++i) {
      if (m_currentGroups[i].representative.id == m_selectedAlertId) {
        found = i;
        break;
      }
    }
    if (found >= 0 && found < m_rows.size()) {
      m_selectedRow = found;
      m_rows[found]->setSelected(true);
      // Also refresh the detail panel — group occurrence count may
      // have changed if a new alert merged in.
      if (m_detail) {
        const Group& g = m_currentGroups[found];
        m_detail->setAlert(g.representative, g.occurrences);
      }
    } else {
      m_selectedRow = -1;
      m_selectedAlertId.clear();
      if (m_detail)
        m_detail->clear();
    }
  }
}

void AlertsPage::refreshKpis() {
  int total = m_alerts.size();
  int critical = 0, high = 0, recentHour = 0;
  const QDateTime cutoff = QDateTime::currentDateTime().addSecs(-3600);
  for (const EDR::Alert& a : m_alerts) {
    if (a.severity == EDR::Severity::Critical)
      ++critical;
    if (a.severity == EDR::Severity::High)
      ++high;
    if (a.timestamp >= cutoff)
      ++recentHour;
  }
  if (m_kpiTotal)
    m_kpiTotal->setValue(QString::number(total));
  if (m_kpiCritical)
    m_kpiCritical->setValue(QString::number(critical));
  if (m_kpiHigh)
    m_kpiHigh->setValue(QString::number(high));
  if (m_kpiRecent)
    m_kpiRecent->setValue(QString::number(recentHour));
}

void AlertsPage::refreshTimelineLabel() {
  if (!m_timeline || !m_timelineDot || !m_timelineText)
    return;

  if (!m_edrRunning) {
    m_timelineDot->setStyleSheet(QString("QLabel { background-color: %1; border-radius: 4px; }")
                                     .arg(Theme::Color::textMuted));
    m_timelineText->setText(
        "EDR-Lite is OFF. Turn it on in Settings to monitor your "
        "system continuously.");
    return;
  }

  if (!m_haveFirstTick) {
    m_timelineDot->setStyleSheet(QString("QLabel { background-color: %1; border-radius: 4px; }")
                                     .arg(Theme::Color::accentBlue));
    m_timelineText->setText("EDR-Lite is running. Awaiting first tick…");
    return;
  }

  m_timelineDot->setStyleSheet(QString("QLabel { background-color: %1; border-radius: 4px; }")
                                   .arg(Theme::Color::severitySafe));

  QString detail = QString("Last EDR tick %1").arg(relTime(m_lastTickAt));
  if (m_lastTickNewAlerts > 0) {
    detail += QString(" · %1 new alert%2 this tick")
                  .arg(m_lastTickNewAlerts)
                  .arg(m_lastTickNewAlerts == 1 ? "" : "s");
  } else {
    detail += " · no new alerts this tick";
  }
  m_timelineText->setText(detail);
}

// ============================================================================
//  Slots
// ============================================================================
void AlertsPage::onRowClicked(int displayIndex) {
  if (displayIndex < 0 || displayIndex >= m_rows.size())
    return;

  if (m_selectedRow >= 0 && m_selectedRow < m_rows.size())
    m_rows[m_selectedRow]->setSelected(false);

  m_selectedRow = displayIndex;
  m_rows[displayIndex]->setSelected(true);

  if (displayIndex < m_currentGroups.size() && m_detail) {
    const Group& g = m_currentGroups[displayIndex];
    m_selectedAlertId = g.representative.id;
    m_detail->setAlert(g.representative, g.occurrences);
  }
}

void AlertsPage::onFiltersChanged() {
  // Filtering changes the row set — try to keep the selection if the
  // selected alert still passes filters; otherwise drop it.
  rebuildList();
}

void AlertsPage::onTimelineRefresh() {
  refreshTimelineLabel();
}

void AlertsPage::onOpenLocationRequested(const QString& path) {
  // The detail panel already tries QDesktopServices for paths that exist
  // on disk. This slot covers the case where sourcePath is a process
  // name or otherwise non-FS — we don't have a meaningful location to
  // open, so just no-op (the user will see nothing happen, which matches
  // the disabled-state expectation).
  Q_UNUSED(path);
}
