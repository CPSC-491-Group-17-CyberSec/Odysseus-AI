// ============================================================================
// SystemStatusPanel.cpp
// ============================================================================

#include "SystemStatusPanel.h"

#include <QFileInfo>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QWidget>

#include "../theme/DashboardTheme.h"

namespace {

// Color for severity badges
QString severityColor(const QString& sev) {
  const QString s = sev.toLower();
  if (s == "high" || s == "critical")
    return "#C62828";
  if (s == "medium")
    return "#E65100";
  if (s == "low")
    return "#2E7D32";
  return "#888888";
}

QString severityBg(const QString& sev) {
  const QString s = sev.toLower();
  if (s == "high" || s == "critical")
    return "#FDECEA";
  if (s == "medium")
    return "#FFF3E0";
  if (s == "low")
    return "#E8F5E9";
  return "#F0F0F0";
QString severityColor(const QString& sev)
{
    const QString s = sev.toLower();
    if (s == "high"     || s == "critical") return "#C62828";
    if (s == "medium")                       return "#E65100";
    if (s == "low")                          return "#2E7D32";
    if (s == "info"     || s == "informational") return "#1976D2"; // blue
    return "#888888";
}

QString severityBg(const QString& sev)
{
    const QString s = sev.toLower();
    if (s == "high"     || s == "critical") return "#FDECEA";
    if (s == "medium")                       return "#FFF3E0";
    if (s == "low")                          return "#E8F5E9";
    if (s == "info"     || s == "informational") return "#E3F2FD"; // light blue
    return "#F0F0F0";
}

}  // namespace

SystemStatusPanel::SystemStatusPanel(QWidget* parent)
    : QFrame(parent) {
  buildUi();
}

void SystemStatusPanel::buildUi() {
  // Step 5 polish — dark theme matching the rest of the app.
  setStyleSheet(QString("QFrame { background-color: %1; border-radius: 15px; color: %2; }")
                    .arg(Theme::Color::bgPrimary, Theme::Color::textPrimary));

  // Outer layout: header + scroll-area-wrapped content (Phase 3 made the
  // panel taller; we let it scroll instead of clipping inside the frame).
  auto* outerLayout = new QVBoxLayout(this);
  outerLayout->setContentsMargins(20, 16, 20, 16);
  outerLayout->setSpacing(8);

  // ── Header (always visible, not scrolled) ───────────────────────────
  auto* headerRow = new QHBoxLayout();
  auto* title = new QLabel("System Status");
  title->setStyleSheet(QString("color: %1; %2")
                           .arg(Theme::Color::textPrimary)
                           .arg(Theme::Type::qss(Theme::Type::Display, Theme::Type::WeightBold)));

  m_refreshBtn = new QPushButton("Refresh");
  m_refreshBtn->setCursor(Qt::PointingHandCursor);
  m_refreshBtn->setStyleSheet(
      "QPushButton { background-color: #1A1AEE; color: white; border-radius: 12px;"
      " padding: 6px 18px; font-weight: bold; }"
      "QPushButton:hover { background-color: #0000CC; }"
      "QPushButton:disabled { background-color: #888; }");

  m_closeBtn = new QPushButton("Close");
  m_closeBtn->setCursor(Qt::PointingHandCursor);
  m_closeBtn->setStyleSheet(
      "QPushButton { background-color: #DDD; color: #333; border-radius: 12px;"
      " padding: 6px 18px; }"
      "QPushButton:hover { background-color: #CCC; }");

  headerRow->addWidget(title);
  headerRow->addStretch();
  headerRow->addWidget(m_refreshBtn);
  headerRow->addWidget(m_closeBtn);
  outerLayout->addLayout(headerRow);

  m_subTitle = new QLabel("Click Refresh to capture a snapshot.");
  m_subTitle->setStyleSheet(QString("color: %1; %2 background: transparent;")
                                .arg(Theme::Color::textSecondary)
                                .arg(Theme::Type::qss(Theme::Type::Small)));
  outerLayout->addWidget(m_subTitle);

  // ── Scroll area ─────────────────────────────────────────────────────
  auto* scroll = new QScrollArea();
  scroll->setWidgetResizable(true);
  scroll->setFrameShape(QFrame::NoFrame);
  scroll->setStyleSheet("QScrollArea { background-color: transparent; }");

  auto* scrollContent = new QWidget();
  scrollContent->setStyleSheet("background-color: transparent;");
  auto* mainLayout = new QVBoxLayout(scrollContent);
  mainLayout->setContentsMargins(0, 0, 0, 0);
  mainLayout->setSpacing(12);

  // ── KPI strip ───────────────────────────────────────────────────────
  auto* kpiRow = new QHBoxLayout();
  kpiRow->setSpacing(10);

  auto buildKpi = [this](const QString& label, QLabel*& valOut) {
    auto* box = new QFrame();
    box->setStyleSheet(QString("QFrame { background-color: %1; border: 1px solid %2;"
                               " border-radius: 8px; }")
                           .arg(Theme::Color::bgCard, Theme::Color::borderSubtle));
    auto* v = new QVBoxLayout(box);
    v->setContentsMargins(12, 8, 12, 8);
    auto* lab = new QLabel(label);
    lab->setStyleSheet("font-size: 11px; color: #888;");
    valOut = new QLabel("—");
    valOut->setStyleSheet(QString("color: %1; %2 background: transparent;")
                              .arg(Theme::Color::textPrimary)
                              .arg(Theme::Type::qss(Theme::Type::H1, Theme::Type::WeightBold)));
    v->addWidget(lab);
    v->addWidget(valOut);
    return box;
  };

  kpiRow->addWidget(buildKpi("Total Processes", m_kpiTotalProcs));
  kpiRow->addWidget(buildKpi("Suspicious", m_kpiSuspicious));
  kpiRow->addWidget(buildKpi("Persistence Items", m_kpiPersistence));
  kpiRow->addWidget(buildKpi("Kernel Ext.", m_kpiKernelExt));  // Phase 3
  kpiRow->addWidget(buildKpi("Integrity", m_kpiIntegrity));    // Phase 3
  kpiRow->addWidget(buildKpi("Platform", m_kpiPlatform));
  mainLayout->addLayout(kpiRow);

  // Reusable list-section builder (Step 5 — dark theme)
  auto buildSection =
      [this, mainLayout](
          const QString& title, const QString& color, QLabel*& headerOut, QListWidget*& listOut) {
    headerOut = new QLabel(title);
    headerOut->setStyleSheet(QString("QLabel { color: %1; %2 padding-top: 6px;"
                                     " background: transparent; }")
                                 .arg(color)
                                 .arg(Theme::Type::qss(Theme::Type::H3, Theme::Type::WeightBold)));
    mainLayout->addWidget(headerOut);

    listOut = new QListWidget();
    listOut->setStyleSheet(QString("QListWidget {"
                                   "  background-color: %1; color: %2;"
                                   "  border: 1px solid %3; border-radius: 8px;"
                                   "  padding: 6px; font-size: %6px;"
                                   "}"
                                   "QListWidget::item {"
                                   "  padding: 8px 10px; border-bottom: 1px solid %3;"
                                   "}"
                                   "QListWidget::item:hover { background-color: %4; }"
                                   "QListWidget::item:selected {"
                                   "  background-color: %5; color: white;"
                                   "}")
                               .arg(
                                   Theme::Color::bgCard,
                                   Theme::Color::textPrimary,
                                   Theme::Color::borderSubtle,
                                   Theme::Color::bgCardHover,
                                   Theme::Color::accentBlueSoft)
                               .arg(Theme::Type::Body));
    listOut->setMinimumHeight(120);
    mainLayout->addWidget(listOut, 1);
  };

  // ── Suspicious processes section (Phase 2) ─────────────────────────
  buildSection("Suspicious Processes (—)", "#C62828", m_suspiciousHeader, m_suspiciousList);
  connect(
      m_suspiciousList, &QListWidget::itemClicked, this, &SystemStatusPanel::onProcessRowClicked);

  // ── Persistence section (Phase 2) ──────────────────────────────────
  buildSection("Persistence Items (—)", "#1565C0", m_persistenceHeader, m_persistenceList);
  connect(
      m_persistenceList,
      &QListWidget::itemClicked,
      this,
      &SystemStatusPanel::onPersistenceRowClicked);

  // ── Cross-view findings (Phase 3) ──────────────────────────────────
  buildSection("Process Cross-View Findings (—)", "#6A1B9A", m_crossViewHeader, m_crossViewList);
  connect(
      m_crossViewList, &QListWidget::itemClicked, this, &SystemStatusPanel::onCrossViewRowClicked);

  // ── Kernel/system extensions (Phase 3) ─────────────────────────────
  buildSection("Kernel / System Extensions (—)", "#00695C", m_extensionsHeader, m_extensionsList);
  connect(
      m_extensionsList, &QListWidget::itemClicked, this, &SystemStatusPanel::onExtensionRowClicked);

  // ── Integrity findings (Phase 3) ───────────────────────────────────
  buildSection("Integrity Findings (—)", "#BF360C", m_integrityHeader, m_integrityList);
  connect(
      m_integrityList, &QListWidget::itemClicked, this, &SystemStatusPanel::onIntegrityRowClicked);

  // ── Detail label (Step 5 — dark theme) ────────────────────────────
  m_detailLabel = new QLabel();
  m_detailLabel->setWordWrap(true);
  m_detailLabel->setTextFormat(Qt::RichText);
  m_detailLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
  m_detailLabel->setStyleSheet(
      QString("QLabel { background-color: %1; border: 1px solid %2;"
              " border-radius: 8px; padding: 12px; color: %3;"
              " font-size: %4px; }")
          .arg(Theme::Color::bgCard, Theme::Color::borderSubtle, Theme::Color::textPrimary)
          .arg(Theme::Type::Body));
  m_detailLabel->setVisible(false);
  mainLayout->addWidget(m_detailLabel);

  scroll->setWidget(scrollContent);
  outerLayout->addWidget(scroll, 1);

  connect(m_refreshBtn, &QPushButton::clicked, this, [this]() {
    m_subTitle->setText("Refreshing…");
    m_refreshBtn->setEnabled(false);
    emit refreshRequested();
  });
  connect(m_closeBtn, &QPushButton::clicked, this, &SystemStatusPanel::closeRequested);
}

void SystemStatusPanel::setRefreshing(bool refreshing) {
  m_refreshBtn->setEnabled(!refreshing);
  if (refreshing)
    m_subTitle->setText("Refreshing…");
}

void SystemStatusPanel::setSnapshot(const SystemSnapshot& snap) {
  m_snapshot = snap;
  m_refreshBtn->setEnabled(true);

  // Subtitle: capture timestamp + restricted-cmdline note if any
  QString sub = QString("Last refresh: %1").arg(snap.capturedAt.toString("yyyy-MM-dd HH:mm:ss"));
  if (snap.restrictedCmdlines > 0) {
    sub += QString(
               "  •  %1 process(es) had restricted metadata "
               "(grant Full Disk Access for full visibility)")
               .arg(snap.restrictedCmdlines);
  }
  m_subTitle->setText(sub);

  // KPIs
  m_kpiTotalProcs->setText(QString::number(snap.totalProcesses));
  m_kpiSuspicious->setText(QString::number(snap.suspicious.size()));
  if (!snap.suspicious.isEmpty())
    m_kpiSuspicious->setStyleSheet("font-size: 22px; font-weight: bold; color: #C62828;");
  else
    m_kpiSuspicious->setStyleSheet("font-size: 22px; font-weight: bold; color: #2E7D32;");
  m_kpiPersistence->setText(QString::number(snap.persistence.size()));
  m_kpiPlatform->setText(snap.platformLabel);
  m_kpiPlatform->setStyleSheet("font-size: 18px; font-weight: bold; color: #333;");

  // Section headers with counts
  m_suspiciousHeader->setText(QString("Suspicious Processes (%1)").arg(snap.suspicious.size()));
  m_persistenceHeader->setText(QString("Persistence Items (%1)").arg(snap.persistence.size()));

  // ── Suspicious list ────────────────────────────────────────────────
  m_suspiciousList->clear();
  if (snap.suspicious.isEmpty()) {
    auto* item = new QListWidgetItem("No suspicious processes detected.");
    item->setForeground(QColor("#2E7D32"));
    item->setFlags(Qt::ItemIsEnabled);
    m_suspiciousList->addItem(item);
  } else {
    for (int i = 0; i < snap.suspicious.size(); ++i) {
      const SuspiciousProcess& sp = snap.suspicious[i];
      const QString summary = QString("[%1]  PID %2  %3  —  score %4  •  %5")
                                  .arg(sp.severity.toUpper())
                                  .arg(sp.info.pid)
                                  .arg(sp.info.name)
                                  .arg(sp.score)
                                  .arg(sp.reasons.first());
      auto* item = new QListWidgetItem(summary);
      item->setForeground(QColor(severityColor(sp.severity)));
      item->setData(Qt::UserRole, i);  // index back into m_snapshot.suspicious
      m_suspiciousList->addItem(item);
    }
  }

  // ── Persistence list ───────────────────────────────────────────────
  m_persistenceList->clear();
  if (snap.persistence.isEmpty()) {
    auto* item = new QListWidgetItem("No persistence items found.");
    item->setForeground(QColor("#888"));
    item->setFlags(Qt::ItemIsEnabled);
    m_persistenceList->addItem(item);
  } else {
    for (int i = 0; i < snap.persistence.size(); ++i) {
      const PersistenceItem& pi = snap.persistence[i];
      const QString prog = pi.program.isEmpty() ? QStringLiteral("(no Program)") : pi.program;
      const QString summary = QString("[%1]  %2  →  %3").arg(pi.type, pi.label, prog);
      auto* item = new QListWidgetItem(summary);
      item->setForeground(QColor(severityColor(pi.severity)));
      item->setData(Qt::UserRole, i);  // index back into m_snapshot.persistence
      m_persistenceList->addItem(item);
    }
  }

  // ════════════════════════════════════════════════════════════════════
  //  Phase 3 — Rootkit awareness sections
  // ════════════════════════════════════════════════════════════════════
  const RootkitSnapshot& rk = snap.rootkit;

  // ── KPI tiles ──────────────────────────────────────────────────────
  m_kpiKernelExt->setText(rk.ran ? QString::number(rk.extensions.size()) : "—");
  if (!rk.ran) {
    m_kpiIntegrity->setText("—");
    m_kpiIntegrity->setStyleSheet("font-size: 18px; font-weight: bold; color: #888;");
  } else if (rk.integrityMismatches > 0) {
    m_kpiIntegrity->setText(QString("%1 \xE2\x9A\xA0").arg(rk.integrityMismatches));
    m_kpiIntegrity->setStyleSheet("font-size: 22px; font-weight: bold; color: #C62828;");
  } else if (rk.baselineCreated) {
    m_kpiIntegrity->setText("baselined");
    m_kpiIntegrity->setStyleSheet("font-size: 14px; font-weight: bold; color: #1565C0;");
  } else if (rk.baselineRebased) {
    m_kpiIntegrity->setText("rebased");
    m_kpiIntegrity->setStyleSheet("font-size: 14px; font-weight: bold; color: #1565C0;");
  } else {
    m_kpiIntegrity->setText("OK");
    m_kpiIntegrity->setStyleSheet("font-size: 22px; font-weight: bold; color: #2E7D32;");
  }

  // ── Cross-view list ────────────────────────────────────────────────
  m_crossViewHeader->setText(QString("Process Cross-View Findings (%1)").arg(rk.crossView.size()));
  m_crossViewList->clear();
  if (!rk.ran) {
    auto* item = new QListWidgetItem("Rootkit awareness disabled in configuration.");
    item->setForeground(QColor("#888"));
    item->setFlags(Qt::ItemIsEnabled);
    m_crossViewList->addItem(item);
  } else if (rk.crossView.isEmpty()) {
    auto* item = new QListWidgetItem(QString("No process-list disagreements (sysctl=%1, ps=%2).")
                                         .arg(rk.processSysctlCount)
                                         .arg(rk.processPsCount));
    item->setForeground(QColor("#2E7D32"));
    item->setFlags(Qt::ItemIsEnabled);
    m_crossViewList->addItem(item);
  } else {
    for (int i = 0; i < rk.crossView.size(); ++i) {
      const CrossViewFinding& f = rk.crossView[i];
      const QString summary = QString("[%1]  PID %2  %3  \xE2\x80\x94  %4")
                                  .arg(f.severity.toUpper())
                                  .arg(f.pid)
                                  .arg(f.name)
                                  .arg(f.visibleIn);
      auto* item = new QListWidgetItem(summary);
      item->setForeground(QColor(severityColor(f.severity)));
      item->setData(Qt::UserRole, i);
      m_crossViewList->addItem(item);
    }
  }

  // ── Extensions list ────────────────────────────────────────────────
  m_extensionsHeader->setText(QString("Kernel / System Extensions (%1)").arg(rk.extensions.size()));
  m_extensionsList->clear();
  if (!rk.ran) {
    auto* item = new QListWidgetItem("Rootkit awareness disabled in configuration.");
    item->setForeground(QColor("#888"));
    item->setFlags(Qt::ItemIsEnabled);
    m_extensionsList->addItem(item);
  } else if (rk.extensions.isEmpty()) {
    auto* item = new QListWidgetItem(
        "No kernel or system extensions found "
        "(unprivileged enumeration may be incomplete).");
    item->setForeground(QColor("#888"));
    item->setFlags(Qt::ItemIsEnabled);
    m_extensionsList->addItem(item);
  } else {
    for (int i = 0; i < rk.extensions.size(); ++i) {
      const KernelExtension& k = rk.extensions[i];
      const QString tag =
          k.isApple ? "Apple"
                    : (k.teamId.isEmpty() ? "(no teamID)" : QString("teamID:%1").arg(k.teamId));
      const QString summary = QString("[%1]  %2  %3  \xE2\x80\x94  %4  \xE2\x80\xA2  %5")
                                  .arg(k.severity.toUpper())
                                  .arg(k.source)
                                  .arg(k.bundleId)
                                  .arg(k.version.isEmpty() ? "?" : k.version)
                                  .arg(tag);
      auto* item = new QListWidgetItem(summary);
      item->setForeground(QColor(severityColor(k.severity)));
      item->setData(Qt::UserRole, i);
      m_extensionsList->addItem(item);
    }
  }

  // ── Integrity list ─────────────────────────────────────────────────
  m_integrityHeader->setText(QString("Integrity Findings (%1, %2 mismatch(es))")
                                 .arg(rk.integrity.size())
                                 .arg(rk.integrityMismatches));
  m_integrityList->clear();
  if (!rk.ran) {
    auto* item = new QListWidgetItem("Rootkit awareness disabled in configuration.");
    item->setForeground(QColor("#888"));
    item->setFlags(Qt::ItemIsEnabled);
    m_integrityList->addItem(item);
  } else if (rk.integrity.isEmpty()) {
    auto* item = new QListWidgetItem("No critical paths checked (integrity check disabled).");
    item->setForeground(QColor("#888"));
    item->setFlags(Qt::ItemIsEnabled);
    m_integrityList->addItem(item);
  } else {
    for (int i = 0; i < rk.integrity.size(); ++i) {
      const IntegrityFinding& f = rk.integrity[i];
      const QString summary =
          QString("[%1]  %2  \xE2\x86\x92  %3").arg(f.status.toUpper()).arg(f.path).arg(f.note);
      auto* item = new QListWidgetItem(summary);
      item->setForeground(QColor(severityColor(f.severity)));
      item->setData(Qt::UserRole, i);
      m_integrityList->addItem(item);
    }
  }

  // Reset detail
  m_detailLabel->setVisible(false);
}

void SystemStatusPanel::onProcessRowClicked(QListWidgetItem* item) {
  if (!item)
    return;
  const int idx = item->data(Qt::UserRole).toInt();
  if (idx < 0 || idx >= m_snapshot.suspicious.size())
    return;
  const SuspiciousProcess& sp = m_snapshot.suspicious[idx];

  QString html;
  html += QString("<b>PID %1 — %2</b>").arg(sp.info.pid).arg(sp.info.name);
  html += QString(
              "<span style='background-color:%1; color:%2; padding:2px 8px;"
              " border-radius:6px; margin-left:10px; font-weight:bold;'>%3</span><br>")
              .arg(severityBg(sp.severity), severityColor(sp.severity), sp.severity.toUpper());

  html += QString(
              "<span style='color:#666;'>User:</span> %1 &nbsp;"
              "<span style='color:#666;'>PPID:</span> %2 &nbsp;"
              "<span style='color:#666;'>Score:</span> %3<br>")
              .arg(sp.info.user)
              .arg(sp.info.ppid)
              .arg(sp.score);

  if (!sp.info.exePath.isEmpty()) {
    html += QString(
                "<span style='color:#666;'>Exe:</span> "
                "<code>%1</code>%2<br>")
                .arg(sp.info.exePath)
                .arg(sp.info.exeMissing ? " <b style='color:#C62828;'>(MISSING)</b>" : "");
  }
  if (!sp.info.cmdLine.isEmpty()) {
    QString cl = sp.info.cmdLine;
    if (cl.length() > 200)
      cl = cl.left(200) + "…";
    html += QString("<span style='color:#666;'>Cmd:</span> <code>%1</code><br>")
                .arg(cl.toHtmlEscaped());
  }
  if (sp.signingStatus >= 0) {
    QString sgn;
    switch (sp.signingStatus) {
      case 2:
        sgn = "<span style='color:#2E7D32;'>signed (trusted)</span>";
        break;
      case 1:
        sgn = "<span style='color:#E65100;'>signed (untrusted)</span>";
        break;
      case 0:
        sgn = "<span style='color:#C62828;'>UNSIGNED</span>";
        break;
      default:
        sgn = "unknown";
        break;
    }
    html += QString("<span style='color:#666;'>Signature:</span> %1").arg(sgn);
    if (!sp.signerId.isEmpty())
      html += QString(" — %1").arg(sp.signerId.toHtmlEscaped());
    html += "<br>";
  }

  html += "<br><b>Why flagged:</b><ul style='margin-top:4px;'>";
  for (const QString& r : sp.reasons)
    html += QString("<li>%1</li>").arg(r.toHtmlEscaped());
  html += "</ul>";

  m_detailLabel->setText(html);
  m_detailLabel->setVisible(true);
}

void SystemStatusPanel::onPersistenceRowClicked(QListWidgetItem* item) {
  if (!item)
    return;
  const int idx = item->data(Qt::UserRole).toInt();
  if (idx < 0 || idx >= m_snapshot.persistence.size())
    return;
  const PersistenceItem& pi = m_snapshot.persistence[idx];

  QString html;
  html += QString("<b>%1</b>").arg(pi.label.toHtmlEscaped());
  html += QString(
              "<span style='background-color:%1; color:%2; padding:2px 8px;"
              " border-radius:6px; margin-left:10px; font-weight:bold;'>%3</span><br>")
              .arg(severityBg(pi.severity), severityColor(pi.severity), pi.severity.toUpper());
  html += QString("<span style='color:#666;'>Type:</span> %1<br>").arg(pi.type);
  if (!pi.filePath.isEmpty())
    html += QString("<span style='color:#666;'>File:</span> <code>%1</code><br>")
                .arg(pi.filePath.toHtmlEscaped());
  if (!pi.program.isEmpty())
    html += QString("<span style='color:#666;'>Program:</span> <code>%1</code><br>")
                .arg(pi.program.toHtmlEscaped());
  if (!pi.programArgs.isEmpty())
    html += QString("<span style='color:#666;'>Args:</span> <code>%1</code><br>")
                .arg(pi.programArgs.join(' ').toHtmlEscaped());
  if (!pi.scheduleHint.isEmpty())
    html += QString("<span style='color:#666;'>Schedule:</span> %1<br>")
                .arg(pi.scheduleHint.toHtmlEscaped());
  if (pi.runAtLoad)
    html += "RunAtLoad: <b>YES</b><br>";
  if (pi.keepAlive)
    html += "KeepAlive: <b>YES</b><br>";
  if (!pi.notes.isEmpty()) {
    html += "<br><b>Notes:</b><ul style='margin-top:4px;'>";
    for (const QString& n : pi.notes)
      html += QString("<li>%1</li>").arg(n.toHtmlEscaped());
    html += "</ul>";
  }

  m_detailLabel->setText(html);
  m_detailLabel->setVisible(true);
}

// ════════════════════════════════════════════════════════════════════════
//  Phase 3 detail click handlers
// ════════════════════════════════════════════════════════════════════════
void SystemStatusPanel::onCrossViewRowClicked(QListWidgetItem* item) {
  if (!item)
    return;
  const int idx = item->data(Qt::UserRole).toInt();
  if (idx < 0 || idx >= m_snapshot.rootkit.crossView.size())
    return;
  const CrossViewFinding& f = m_snapshot.rootkit.crossView[idx];

  QString html;
  html += QString("<b>PID %1 — %2</b>").arg(f.pid).arg(f.name.toHtmlEscaped());
  html += QString(
              "<span style='background-color:%1; color:%2; padding:2px 8px;"
              " border-radius:6px; margin-left:10px; font-weight:bold;'>%3</span><br>")
              .arg(severityBg(f.severity), severityColor(f.severity), f.severity.toUpper());
  html += QString("<span style='color:#666;'>Visibility:</span> <b>%1</b><br>").arg(f.visibleIn);
  html += QString("<br>%1").arg(f.reason.toHtmlEscaped());

  html +=
      "<br><br><i style='color:#888; font-size:11px;'>Note: a single "
      "transient mismatch can occur when a process exits between the "
      "two snapshots. Re-run Refresh; if the same PID still mismatches, "
      "investigate further.</i>";

  m_detailLabel->setText(html);
  m_detailLabel->setVisible(true);
}

void SystemStatusPanel::onExtensionRowClicked(QListWidgetItem* item) {
  if (!item)
    return;
  const int idx = item->data(Qt::UserRole).toInt();
  if (idx < 0 || idx >= m_snapshot.rootkit.extensions.size())
    return;
  const KernelExtension& k = m_snapshot.rootkit.extensions[idx];

  QString html;
  html += QString("<b>%1</b>").arg(k.bundleId.toHtmlEscaped());
  html += QString(
              "<span style='background-color:%1; color:%2; padding:2px 8px;"
              " border-radius:6px; margin-left:10px; font-weight:bold;'>%3</span><br>")
              .arg(severityBg(k.severity), severityColor(k.severity), k.severity.toUpper());
  html += QString(
              "<span style='color:#666;'>Source:</span> %1 "
              "(%2)<br>")
              .arg(k.source)
              .arg(k.isUserspace ? "user-space" : "kernel-resident");
  if (!k.name.isEmpty() && k.name != k.bundleId)
    html += QString("<span style='color:#666;'>Name:</span> %1<br>").arg(k.name.toHtmlEscaped());
  if (!k.version.isEmpty())
    html += QString("<span style='color:#666;'>Version:</span> %1<br>").arg(k.version);
  if (!k.teamId.isEmpty())
    html += QString(
                "<span style='color:#666;'>Team ID:</span> "
                "<code>%1</code><br>")
                .arg(k.teamId);
  if (!k.signedBy.isEmpty())
    html += QString("<span style='color:#666;'>Signed by:</span> %1<br>")
                .arg(k.signedBy.toHtmlEscaped());
  if (!k.state.isEmpty())
    html += QString("<span style='color:#666;'>State:</span> %1<br>").arg(k.state.toHtmlEscaped());
  if (!k.notes.isEmpty()) {
    html += "<br><b>Notes:</b><ul style='margin-top:4px;'>";
    for (const QString& n : k.notes)
      html += QString("<li>%1</li>").arg(n.toHtmlEscaped());
    html += "</ul>";
  }

  m_detailLabel->setText(html);
  m_detailLabel->setVisible(true);
}

void SystemStatusPanel::onIntegrityRowClicked(QListWidgetItem* item) {
  if (!item)
    return;
  const int idx = item->data(Qt::UserRole).toInt();
  if (idx < 0 || idx >= m_snapshot.rootkit.integrity.size())
    return;
  const IntegrityFinding& f = m_snapshot.rootkit.integrity[idx];

  QString html;
  html += QString("<b><code>%1</code></b>").arg(f.path.toHtmlEscaped());
  html += QString(
              "<span style='background-color:%1; color:%2; padding:2px 8px;"
              " border-radius:6px; margin-left:10px; font-weight:bold;'>%3</span><br>")
              .arg(severityBg(f.severity), severityColor(f.severity), f.status.toUpper());

  if (!f.note.isEmpty())
    html += QString("<br>%1<br>").arg(f.note.toHtmlEscaped());

  if (!f.expectedHash.isEmpty()) {
    html += QString(
                "<br><span style='color:#666;'>Baseline SHA-256:</span><br>"
                "<code style='font-size:11px;'>%1</code><br>")
                .arg(f.expectedHash);
  }
  if (!f.currentHash.isEmpty()) {
    html += QString(
                "<span style='color:#666;'>Current SHA-256:</span><br>"
                "<code style='font-size:11px;'>%1</code><br>")
                .arg(f.currentHash);
  }
  if (f.currentSize > 0)
    html += QString("<span style='color:#666;'>Size:</span> %1 bytes<br>").arg(f.currentSize);

  if (f.status == "mismatch") {
    html +=
        "<br><i style='color:#C62828; font-size:12px;'>"
        "INTEGRITY VIOLATION. The file's SHA-256 does not match the "
        "baseline captured on this OS version. Possible causes: "
        "tampering, filesystem corruption, or an out-of-band update. "
        "Investigate before trusting this binary.</i>";
  }

  m_detailLabel->setText(html);
  m_detailLabel->setVisible(true);
}
