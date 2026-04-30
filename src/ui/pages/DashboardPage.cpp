// ============================================================================
// DashboardPage.cpp
// ============================================================================

#include "DashboardPage.h"

#include <QFileInfo>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QScrollArea>
#include <QVBoxLayout>

#include "../theme/DashboardTheme.h"
#include "../widgets/ActivityList.h"
#include "../widgets/DonutChart.h"
#include "../widgets/ScanTypeSelector.h"
#include "../widgets/SecurityScoreCard.h"
#include "../widgets/StatCard.h"

namespace {

QString severitySafeNum(int n) {
  return QString("%L1").arg(n);  // adds thousands separators
}

}  // namespace

DashboardPage::DashboardPage(QWidget* parent)
    : QWidget(parent) {
  setStyleSheet(QString("background-color: %1;").arg(Theme::Color::bgPrimary));

  // ── Outer scroll wrapper ──────────────────────────────────────────
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
  // Stabilization E — standardized spacing across the dashboard:
  //   • outer page padding: 32px sides, 28px top/bottom
  //   • section gap: 20px (between KPI row, scan row, bottom row)
  //   • card padding (set per card): 16–20px
  main->setContentsMargins(32, 28, 32, 28);
  main->setSpacing(20);

  // ── Welcome header ────────────────────────────────────────────────
  auto* welcomeBox = new QVBoxLayout();
  welcomeBox->setSpacing(4);
  m_welcomeTitle = new QLabel(QString("Welcome back, User \xF0\x9F\x91\x8B"), content);
  m_welcomeTitle->setStyleSheet(
      QString("color: %1; font-size: 24px; font-weight: 700;").arg(Theme::Color::textPrimary));
  welcomeBox->addWidget(m_welcomeTitle);

  m_welcomeSub = new QLabel("Here's what's happening with your system today.", content);
  m_welcomeSub->setStyleSheet(
      QString("color: %1; font-size: 13px;").arg(Theme::Color::textSecondary));
  welcomeBox->addWidget(m_welcomeSub);
  main->addLayout(welcomeBox);

  // ── Top KPI strip (4 cards) ───────────────────────────────────────
  auto* kpis = new QHBoxLayout();
  kpis->setSpacing(16);

  m_cardStatus = new StatCard(content);
  m_cardStatus->setTitle("System Status");
  m_cardStatus->setValue("Protected");
  m_cardStatus->setSubtitle("Your system is secure");
  m_cardStatus->setIcon(QString::fromUtf8("\xE2\x9C\x93"));
  m_cardStatus->setTone(StatCard::Safe);
  kpis->addWidget(m_cardStatus, 1);

  m_cardCritical = new StatCard(content);
  m_cardCritical->setTitle("Critical Threats");
  m_cardCritical->setValue("0");
  m_cardCritical->setSubtitle("All clear");
  m_cardCritical->setIcon(QString::fromUtf8("\xE2\x9A\xA0"));
  m_cardCritical->setTone(StatCard::Critical);
  kpis->addWidget(m_cardCritical, 1);

  m_cardSuspicious = new StatCard(content);
  m_cardSuspicious->setTitle("Suspicious Files");
  m_cardSuspicious->setValue("0");
  m_cardSuspicious->setSubtitle("Review recommended");
  m_cardSuspicious->setIcon(QString::fromUtf8("\xE2\x9A\xA0"));
  m_cardSuspicious->setTone(StatCard::Warning);
  kpis->addWidget(m_cardSuspicious, 1);

  m_cardScanned = new StatCard(content);
  m_cardScanned->setTitle("Files Scanned");
  m_cardScanned->setValue("0");
  m_cardScanned->setSubtitle("Total scanned files");
  m_cardScanned->setIcon(QString::fromUtf8("\xE2\x96\xA4"));
  m_cardScanned->setTone(StatCard::Info);
  kpis->addWidget(m_cardScanned, 1);

  // Phase 4 — EDR-Lite status card.
  m_cardEdr = new StatCard(content);
  m_cardEdr->setTitle("EDR-Lite");
  m_cardEdr->setValue("Disabled");
  m_cardEdr->setSubtitle("Enable in Settings");
  m_cardEdr->setIcon("");
  m_cardEdr->setTone(StatCard::Info);
  kpis->addWidget(m_cardEdr, 1);

  main->addLayout(kpis);

  // ── Scan picker | Donut overview row ──────────────────────────────
  auto* midRow = new QHBoxLayout();
  midRow->setSpacing(16);

  m_scanSelector = new ScanTypeSelector(content);
  midRow->addWidget(m_scanSelector, 3);

  // Threat Overview card (donut + legend on the right)
  auto* overview = new QFrame(content);
  overview->setObjectName("OdyOverview");
  overview->setAttribute(Qt::WA_StyledBackground, true);
  overview->setStyleSheet(QString("QFrame#OdyOverview {"
                                  "  background-color: %1;"
                                  "  border: 1px solid %2;"
                                  "  border-radius: %3px;"
                                  "}")
                              .arg(Theme::Color::bgCard, Theme::Color::borderSubtle)
                              .arg(Theme::Size::cardRadius));
  auto* ov = new QVBoxLayout(overview);
  ov->setContentsMargins(20, 16, 20, 16);

  auto* ovHeader = new QHBoxLayout();
  auto* ovTitle = new QLabel("Threat Overview", overview);
  ovTitle->setStyleSheet(
      QString("color: %1; font-size: 16px; font-weight: 700;").arg(Theme::Color::textPrimary));
  ovHeader->addWidget(ovTitle);
  ovHeader->addStretch(1);
  auto* weekLabel = new QLabel("This Week", overview);
  weekLabel->setStyleSheet(QString("color: %1; font-size: 11px; padding: 4px 10px;"
                                   " background-color: %2; border-radius: 6px;")
                               .arg(Theme::Color::textSecondary, Theme::Color::bgPrimary));
  ovHeader->addWidget(weekLabel);
  ov->addLayout(ovHeader);

  auto* donutRow = new QHBoxLayout();
  m_donut = new DonutChart(overview);
  m_donut->setMinimumHeight(200);
  donutRow->addWidget(m_donut, 2);

  // Legend
  auto* legend = new QVBoxLayout();
  legend->setContentsMargins(0, 0, 0, 0);
  legend->setSpacing(10);
  auto buildLegendRow = [overview](
                            const QString& dotColor, const QString& label, QLabel*& valueOut) {
    auto* h = new QHBoxLayout();
    auto* dot = new QLabel("\xE2\x97\x8F", overview);  // ●
    dot->setStyleSheet(QString("color: %1; font-size: 14px;").arg(dotColor));
    h->addWidget(dot);
    auto* lab = new QLabel(label, overview);
    lab->setStyleSheet(QString("color: %1; font-size: 12px;").arg(Theme::Color::textSecondary));
    h->addWidget(lab, 1);
    valueOut = new QLabel("0", overview);
    valueOut->setStyleSheet(
        QString("color: %1; font-size: 12px; font-weight: 600;").arg(Theme::Color::textPrimary));
    h->addWidget(valueOut);
    return h;
  };

  QLabel *legCrit = nullptr, *legSusp = nullptr, *legLow = nullptr, *legClean = nullptr;
  legend->addLayout(buildLegendRow(Theme::Color::severityCritical, "Critical", legCrit));
  legend->addLayout(buildLegendRow(Theme::Color::severityMedium, "Suspicious", legSusp));
  legend->addLayout(buildLegendRow(Theme::Color::severityHigh, "Low Risk", legLow));
  legend->addLayout(buildLegendRow(Theme::Color::severitySafe, "Clean", legClean));
  legend->addStretch(1);

  // Stash legend pointers as properties on the overview so refresh() can
  // find and update them without adding members to the page.
  overview->setProperty("__legCrit", QVariant::fromValue<QObject*>(legCrit));
  overview->setProperty("__legSusp", QVariant::fromValue<QObject*>(legSusp));
  overview->setProperty("__legLow", QVariant::fromValue<QObject*>(legLow));
  overview->setProperty("__legClean", QVariant::fromValue<QObject*>(legClean));

  donutRow->addLayout(legend, 1);
  ov->addLayout(donutRow, 1);

  midRow->addWidget(overview, 4);
  main->addLayout(midRow);

  // ── Activity | Score row ──────────────────────────────────────────
  auto* bottomRow = new QHBoxLayout();
  bottomRow->setSpacing(16);

  m_activity = new ActivityList(content);
  bottomRow->addWidget(m_activity, 3);

  m_score = new SecurityScoreCard(content);
  bottomRow->addWidget(m_score, 2);

  main->addLayout(bottomRow);

  main->addStretch(1);

  scroll->setWidget(content);

  // Forward signals
  connect(m_scanSelector, &ScanTypeSelector::scanRequested, this, &DashboardPage::scanRequested);
  connect(m_activity, &ActivityList::viewAllClicked, this, &DashboardPage::viewAllActivityClicked);

  // Stash overview pointer so refresh() can find legend labels.
  setProperty("__overview", QVariant::fromValue<QObject*>(overview));
}

void DashboardPage::refresh(
    const QVector<SuspiciousFile>& findings,
    const QVector<ScanRecord>& history,
    bool scannerRunning,
    const SystemSnapshot* sysSnapshot) {
  // ── Bucket the current findings ───────────────────────────────────
  int criticalN = 0, suspN = 0, lowN = 0;
  for (const SuspiciousFile& sf : findings) {
    const QString c = sf.classificationLevel.toUpper();
    if (c == "CRITICAL")
      ++criticalN;
    else if (c == "SUSPICIOUS")
      ++suspN;
    else
      ++lowN;
  }

  // ── KPI cards ──────────────────────────────────────────────────────
  if (criticalN > 0) {
    m_cardStatus->setTone(StatCard::Critical);
    m_cardStatus->setValue("At Risk");
    m_cardStatus->setSubtitle("Critical threats detected — review immediately.");
  } else if (scannerRunning) {
    m_cardStatus->setTone(StatCard::Info);
    m_cardStatus->setValue("Scanning");
    m_cardStatus->setSubtitle("Scan in progress…");
  } else {
    m_cardStatus->setTone(StatCard::Safe);
    m_cardStatus->setValue("Protected");
    m_cardStatus->setSubtitle("Your system is secure");
  }

  m_cardCritical->setValue(QString::number(criticalN));
  m_cardCritical->setSubtitle(criticalN > 0 ? "Requires immediate attention" : "All clear");
  m_cardSuspicious->setValue(QString::number(suspN));
  m_cardSuspicious->setSubtitle(suspN > 0 ? "Review recommended" : "No suspicious files");

  int totalScanned = 0;
  if (!history.isEmpty())
    totalScanned = history.first().totalScanned;
  m_cardScanned->setValue(severitySafeNum(totalScanned));
  m_cardScanned->setSubtitle("Total scanned files");

  // ── Donut + legend ────────────────────────────────────────────────
  const int cleanN = qMax(0, totalScanned - criticalN - suspN - lowN);
  QVector<DonutChart::Slice> slices = {
      {"Critical", criticalN, QColor(Theme::Color::severityCritical)},
      {"Suspicious", suspN, QColor(Theme::Color::severityMedium)},
      {"Low Risk", lowN, QColor(Theme::Color::severityHigh)},
      {"Clean", cleanN, QColor(Theme::Color::severitySafe)},
  };
  m_donut->setSlices(slices);
  const int totalThreats = criticalN + suspN + lowN;
  m_donut->setCenterValue(QString::number(totalThreats));
  m_donut->setCenterLabel("Total Threats");

  auto* overview = qobject_cast<QFrame*>(property("__overview").value<QObject*>());
  if (overview) {
    auto setLegend = [overview](const char* prop, int v, int total) {
      auto* lab = qobject_cast<QLabel*>(overview->property(prop).value<QObject*>());
      if (!lab)
        return;
      const double pct = total > 0 ? 100.0 * v / total : 0.0;
      lab->setText(QString("%1 (%2%)").arg(v).arg(QString::number(pct, 'f', total > 0 ? 0 : 0)));
    };
    const int totalAll = totalThreats + cleanN;
    setLegend("__legCrit", criticalN, totalAll);
    setLegend("__legSusp", suspN, totalAll);
    setLegend("__legLow", lowN, totalAll);
    setLegend("__legClean", cleanN, totalAll);
  }

  // ── Activity list (Stabilization D) ───────────────────────────────
  // Classify each event by type so the icon + tone tells the user
  // immediately what they're looking at — Critical / Warning / Info /
  // System.
  QVector<ActivityList::Entry> entries;

  // 1. Recent flagged files (most recent up to 3)
  for (int i = qMin(3, findings.size()) - 1; i >= 0; --i) {
    const SuspiciousFile& sf = findings[i];
    ActivityList::Entry e;
    const QString c = sf.classificationLevel.toUpper();
    e.tone = (c == "CRITICAL")     ? ActivityList::Critical
             : (c == "SUSPICIOUS") ? ActivityList::Warning
                                   : ActivityList::Info;

    // Sentence-cased title: "Critical threat detected: foo.exe"
    QString severityLabel;
    if (c == "CRITICAL")
      severityLabel = "Critical threat detected";
    else if (c == "SUSPICIOUS")
      severityLabel = "Suspicious file detected";
    else if (c == "ANOMALOUS")
      severityLabel = "Anomalous file detected";
    else
      severityLabel = "Threat detected";

    e.title = QString("%1: %2").arg(severityLabel, sf.fileName);
    e.subtitle = sf.filePath;
    e.when = sf.lastModified.isValid() ? sf.lastModified : QDateTime::currentDateTime();
    entries.append(e);
  }

  // 2. Most-recent system-monitor snapshot (if any)
  if (sysSnapshot && sysSnapshot->capturedAt.isValid()) {
    ActivityList::Entry e;
    e.tone = ActivityList::System;
    e.title = "System monitoring update";
    e.subtitle = QString("%1 process(es), %2 suspicious, %3 persistence item(s)")
                     .arg(sysSnapshot->totalProcesses)
                     .arg(sysSnapshot->suspicious.size())
                     .arg(sysSnapshot->persistence.size());
    e.when = sysSnapshot->capturedAt;
    entries.append(e);

    if (sysSnapshot->rootkit.integrityMismatches > 0) {
      ActivityList::Entry m;
      m.tone = ActivityList::Critical;
      m.title = QString("Integrity mismatch — %1 path(s) tampered")
                    .arg(sysSnapshot->rootkit.integrityMismatches);
      m.subtitle = "Critical system binary differs from baseline.";
      m.when = sysSnapshot->capturedAt;
      entries.append(m);
    }
  }

  // 3. Recent scan completions from history
  for (int i = 0; i < qMin(3, history.size()); ++i) {
    const ScanRecord& r = history[i];
    ActivityList::Entry e;
    const bool clean = (r.criticalCount == 0 && r.suspiciousOnly == 0 && r.reviewCount == 0);
    e.tone = clean ? ActivityList::Success : ActivityList::Info;
    e.title = clean ? QString("Scan completed — system clean") : QString("Scan completed");
    e.subtitle = QString("Scanned %L1 files in %2:%3")
                     .arg(r.totalScanned)
                     .arg(r.elapsedSeconds / 60, 2, 10, QChar('0'))
                     .arg(r.elapsedSeconds % 60, 2, 10, QChar('0'));
    e.when = r.timestamp;
    entries.append(e);
  }

  m_activity->setEntries(entries);

  // ── Security score (Stabilization C) ──────────────────────────────
  //
  // Unified formula across file findings + system monitoring + rootkit:
  //
  //   start at 100
  //   -30 per critical file finding
  //   -10 per suspicious file finding
  //    -2 per low-risk / needs-review file finding
  //   -15 per high-severity suspicious process
  //    -5 per medium-severity suspicious process
  //   -25 per integrity mismatch (HIGH SIGNAL — Apple Silicon SSV makes
  //                                 these effectively impossible without
  //                                 active tampering)
  //   -10 per cross-view (sysctl ↔ ps) disagreement
  //
  // Results clamp to 0–100. Color thresholds:
  //   ≥ 80  → Excellent / Good   (green)
  //   50–79 → Moderate / At Risk (yellow)
  //   < 50  → Critical            (red)
  //
  int score = 100;
  score -= 30 * criticalN;
  score -= 10 * suspN;
  score -= 2 * lowN;

  int procHigh = 0, procMed = 0;
  int integrityMismatches = 0;
  int crossViewMismatches = 0;
  if (sysSnapshot) {
    for (const SuspiciousProcess& sp : sysSnapshot->suspicious) {
      const QString sev = sp.severity.toLower();
      if (sev == "high")
        ++procHigh;
      else if (sev == "medium")
        ++procMed;
    }
    integrityMismatches = sysSnapshot->rootkit.integrityMismatches;
    crossViewMismatches = sysSnapshot->rootkit.crossView.size();
  }
  score -= 15 * procHigh;
  score -= 5 * procMed;
  score -= 25 * integrityMismatches;
  score -= 10 * crossViewMismatches;

  score = qBound(0, score, 100);
  m_score->setScore(score);

  // 7-day trend: best-effort from history's per-record counts (we can't
  // retrofit historical SystemSnapshots, so older entries reflect file
  // findings only).
  QVector<int> trend;
  for (int i = 0; i < qMin(7, history.size()); ++i) {
    const ScanRecord& r = history[i];
    int s = 100 - 30 * r.criticalCount - 10 * r.suspiciousOnly - 2 * r.reviewCount;
    trend.prepend(qBound(0, s, 100));
  }
  if (trend.isEmpty())
    trend.append(score);
  m_score->setTrend(trend);
}

// ============================================================================
//  Phase 4 — EDR-Lite hooks
// ============================================================================
void DashboardPage::setEdrStatus(bool enabled, const QDateTime& lastTick, int alertCount) {
  if (!m_cardEdr)
    return;

  if (!enabled) {
    m_cardEdr->setTone(StatCard::Info);
    m_cardEdr->setValue("Disabled");
    m_cardEdr->setSubtitle("Enable in Settings");
    return;
  }

  // Tone follows alert pressure: any alerts → Critical, otherwise Safe.
  if (alertCount > 0) {
    m_cardEdr->setTone(StatCard::Critical);
    m_cardEdr->setValue(QString("%1 alert%2").arg(alertCount).arg(alertCount == 1 ? "" : "s"));
  } else {
    m_cardEdr->setTone(StatCard::Safe);
    m_cardEdr->setValue("Active");
  }

  if (lastTick.isValid()) {
    const qint64 secs = lastTick.secsTo(QDateTime::currentDateTime());
    QString rel;
    if (secs < 60)
      rel = QString("Last check %1 sec ago").arg(secs);
    else if (secs < 3600)
      rel = QString("Last check %1 min ago").arg(secs / 60);
    else
      rel = QString("Last check %1 hr ago").arg(secs / 3600);
    m_cardEdr->setSubtitle(rel);
  } else {
    m_cardEdr->setSubtitle("Waiting for first tick…");
  }
}

void DashboardPage::setSecurityReport(const EDR::ScoreReport& report) {
  // Risk-based path replaces the legacy file-finding score.
  if (m_score)
    m_score->setReport(report);
}

void DashboardPage::appendEdrAlert(const EDR::Alert& alert) {
  if (!m_activity)
    return;

  // Build a one-shot ActivityList::Entry. We don't try to keep the
  // whole alert log here — that's the Alerts page. The dashboard just
  // shows the most-recent few alongside scan events.
  ActivityList::Entry e;
  switch (alert.severity) {
    case EDR::Severity::Critical:
      e.tone = ActivityList::Critical;
      break;
    case EDR::Severity::High:
      e.tone = ActivityList::Critical;
      break;
    case EDR::Severity::Medium:
      e.tone = ActivityList::Warning;
      break;
    case EDR::Severity::Low:
      e.tone = ActivityList::Info;
      break;
    default:
      e.tone = ActivityList::System;
      break;
  }
  e.title = alert.title;
  e.subtitle = alert.sourcePath;
  e.when = alert.timestamp.isValid() ? alert.timestamp : QDateTime::currentDateTime();

  // We rebuild the whole list each time to keep the dashboard's existing
  // "scan events + system snapshot + flagged files" logic intact. The
  // simplest path: prepend the new alert to a small list and let the
  // next refresh() rebuild things. For now, just shove it at the top
  // by re-using setEntries with a single new item kept in m_lastEdrEntry.
  QVector<ActivityList::Entry> existing;
  existing.append(e);
  m_activity->setEntries(existing);
}
