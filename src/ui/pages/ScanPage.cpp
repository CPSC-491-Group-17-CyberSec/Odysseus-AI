// ============================================================================
// ScanPage.cpp
// ============================================================================

#include "ScanPage.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QDirIterator>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QListWidgetItem>
#include <QPushButton>
#include <QProgressBar>      // progress strip
#include <QScrollArea>
#include <QStandardPaths>
#include <QStorageInfo>
#include <QTimer>            // elapsed-time tick
#include <QDateTime>
#include <QVBoxLayout>

#include "../theme/DashboardTheme.h"
#include "../widgets/DropArea.h"
#include "../widgets/StatCard.h"

namespace {

QString cardQss() {
  return QString(
             "QFrame#OdyScanCard {"
             "  background-color: %1;"
             "  border: 1px solid %2;"
             "  border-radius: 12px;"
             "}")
      .arg(Theme::Color::bgCard, Theme::Color::borderSubtle);
}

QString primaryButtonQss() {
  return QString(
             "QPushButton {"
             "  background-color: %1; color: white; border: none;"
             "  border-radius: 8px; padding: 10px 18px; %2"
             "}"
             "QPushButton:hover { background-color: %3; }"
             "QPushButton:disabled { background-color: %4; color: %5; }")
      .arg(Theme::Color::accentBlue)
      .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi))
      .arg(Theme::Color::accentBlueHover)
      .arg(Theme::Color::bgSecondary)
      .arg(Theme::Color::textMuted);
}

QString secondaryButtonQss() {
  return QString(
             "QPushButton {"
             "  background-color: %1; color: %2;"
             "  border: 1px solid %3; border-radius: 8px;"
             "  padding: 9px 14px; %4"
             "}"
             "QPushButton:hover { background-color: %5; color: white; }")
      .arg(Theme::Color::bgSecondary, Theme::Color::textPrimary, Theme::Color::borderSubtle)
      .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi))
      .arg(Theme::Color::accentBlueSoft);
}

QString comboQss() {
  return QString(
             "QComboBox {"
             "  background-color: %1; color: %2;"
             "  border: 1px solid %3; border-radius: 8px;"
             "  padding: 8px 12px; %4"
             "}"
             "QComboBox::drop-down { border: none; width: 24px; }"
             "QComboBox QAbstractItemView {"
             "  background-color: %1; color: %2;"
             "  selection-background-color: %5; border: 1px solid %3;"
             "}")
      .arg(Theme::Color::bgSecondary, Theme::Color::textPrimary, Theme::Color::borderSubtle)
      .arg(Theme::Type::qss(Theme::Type::Body))
      .arg(Theme::Color::accentBlueSoft);
}

QString checkboxQss() {
  return QString(
             "QCheckBox { color: %1; %2 background: transparent;"
             " spacing: 10px; }"
             "QCheckBox::indicator {"
             "  width: 18px; height: 18px;"
             "  background-color: %3;"
             "  border: 1px solid %4; border-radius: 4px;"
             "}"
             "QCheckBox::indicator:checked {"
             "  background-color: %5;"
             "  border-color: %5;"
             "}")
      .arg(Theme::Color::textPrimary)
      .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi))
      .arg(Theme::Color::bgSecondary)
      .arg(Theme::Color::borderSubtle)
      .arg(Theme::Color::accentBlue);
}

}  // namespace

// ============================================================================
//  Construction
// ============================================================================
ScanPage::ScanPage(QWidget* parent)
    : QWidget(parent) {
  setStyleSheet(QString("background-color: %1;").arg(Theme::Color::bgPrimary));
  buildUi();
  rebuildTargetList();
  rebuildRecentScans();
  setStats({}, 0, 0, true, false);
}

void ScanPage::buildUi() {
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
  main->setSpacing(24);

  // ── Header ─────────────────────────────────────────────────────────
  auto* titleCol = new QVBoxLayout();
  titleCol->setSpacing(2);

  auto* title = new QLabel("Scan", content);
  title->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                           .arg(Theme::Color::textPrimary)
                           .arg(Theme::Type::qss(Theme::Type::Display, Theme::Type::WeightBold)));
  titleCol->addWidget(title);

  auto* subtitle = new QLabel("Configure and run AI-powered threat scans", content);
  subtitle->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                              .arg(Theme::Color::textSecondary)
                              .arg(Theme::Type::qss(Theme::Type::Body)));
  titleCol->addWidget(subtitle);
  main->addLayout(titleCol);

  // ── KPI strip (4 StatCards) ───────────────────────────────────────
  auto* kpiRow = new QHBoxLayout();
  kpiRow->setSpacing(16);

  m_kpiLastScan = new StatCard(content);
  m_kpiLastScan->setTone(StatCard::Info);
  m_kpiLastScan->setTitle("LAST SCAN");
  m_kpiLastScan->setValue("—");
  m_kpiLastScan->setSubtitle("No scans yet");
  m_kpiLastScan->setIcon("");
  kpiRow->addWidget(m_kpiLastScan, 1);

  m_kpiFilesScanned = new StatCard(content);
  m_kpiFilesScanned->setTone(StatCard::Info);
  m_kpiFilesScanned->setTitle("FILES SCANNED");
  m_kpiFilesScanned->setValue("0");
  m_kpiFilesScanned->setSubtitle("Total files");
  m_kpiFilesScanned->setIcon("");
  kpiRow->addWidget(m_kpiFilesScanned, 1);

  m_kpiThreatsFound = new StatCard(content);
  m_kpiThreatsFound->setTone(StatCard::Critical);
  m_kpiThreatsFound->setTitle("THREATS FOUND");
  m_kpiThreatsFound->setValue("0");
  m_kpiThreatsFound->setSubtitle("No threats detected");
  m_kpiThreatsFound->setIcon("");
  kpiRow->addWidget(m_kpiThreatsFound, 1);

  m_kpiStatus = new StatCard(content);
  m_kpiStatus->setTone(StatCard::Safe);
  m_kpiStatus->setTitle("STATUS");
  m_kpiStatus->setValue("Ready");
  m_kpiStatus->setSubtitle("System protected");
  m_kpiStatus->setIcon("");
  kpiRow->addWidget(m_kpiStatus, 1);

  main->addLayout(kpiRow);

  // ── Progress strip (sits directly under the KPI row, above the grid) ──
  // Hidden until the first scan starts. Once a scan has run, the strip
  // stays visible so the user can see the final "Scan Complete" state.
  // UI-only — no backend changes; data flows in from MainWindow via
  // setProgress() / setLiveCounts() / setScanning().
  m_progressStrip = new QFrame(content);
  m_progressStrip->setObjectName("OdyScanProgressStrip");
  m_progressStrip->setAttribute(Qt::WA_StyledBackground, true);
  m_progressStrip->setStyleSheet(QString(
      "QFrame#OdyScanProgressStrip {"
      "  background-color: %1;"
      "  border: 1px solid %2;"
      "  border-radius: 12px;"
      "}").arg(Theme::Color::bgCard, Theme::Color::borderSubtle));

  auto* stripLayout = new QVBoxLayout(m_progressStrip);
  stripLayout->setContentsMargins(20, 14, 20, 14);
  stripLayout->setSpacing(10);

  // First row: phase text on the left, percent + elapsed on the right.
  auto* stripTopRow = new QHBoxLayout();
  stripTopRow->setSpacing(16);

  m_progressPhase = new QLabel("Idle", m_progressStrip);
  m_progressPhase->setStyleSheet(QString(
      "QLabel { color: %1; %2 background: transparent; }")
        .arg(Theme::Color::textPrimary)
        .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi)));
  stripTopRow->addWidget(m_progressPhase, 1);

  m_progressPct = new QLabel("0%", m_progressStrip);
  m_progressPct->setStyleSheet(QString(
      "QLabel { color: %1; %2 background: transparent; }")
        .arg(Theme::Color::textSecondary)
        .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi)));
  stripTopRow->addWidget(m_progressPct, 0);

  m_elapsedLabel = new QLabel("Elapsed: 00:00", m_progressStrip);
  m_elapsedLabel->setStyleSheet(QString(
      "QLabel { color: %1; %2 background: transparent; }")
        .arg(Theme::Color::textSecondary)
        .arg(Theme::Type::qss(Theme::Type::Body)));
  stripTopRow->addWidget(m_elapsedLabel, 0);

  stripLayout->addLayout(stripTopRow);

  // Progress bar — dark theme, blue fill matching the brand accent.
  m_progressBar = new QProgressBar(m_progressStrip);
  m_progressBar->setRange(0, 100);
  m_progressBar->setValue(0);
  m_progressBar->setTextVisible(false);
  m_progressBar->setFixedHeight(8);
  m_progressBar->setStyleSheet(QString(
      "QProgressBar {"
      "  background-color: %1;"
      "  border: 1px solid %2;"
      "  border-radius: 4px;"
      "}"
      "QProgressBar::chunk {"
      "  background-color: %3;"
      "  border-radius: 3px;"
      "}").arg(Theme::Color::bgSecondary,
              Theme::Color::borderSubtle,
              Theme::Color::accentBlue));
  stripLayout->addWidget(m_progressBar);

  // Hidden by default (only shown once a scan starts).
  m_progressStrip->setVisible(false);

  main->addWidget(m_progressStrip);

  // Elapsed-time ticker — created once, started/stopped by setScanning().
  m_elapsedTimer = new QTimer(this);
  m_elapsedTimer->setInterval(1000);
  connect(m_elapsedTimer, &QTimer::timeout, this, [this]() {
    if (!m_scanStarted.isValid() || !m_elapsedLabel) return;
    const qint64 secs = m_scanStarted.secsTo(QDateTime::currentDateTime());
    m_elapsedLabel->setText(
        QString("Elapsed: %1:%2")
            .arg(secs / 60, 2, 10, QChar('0'))
            .arg(secs % 60, 2, 10, QChar('0')));
  });

  // ── Main 3-column grid ────────────────────────────────────────────
  auto* grid = new QHBoxLayout();
  grid->setSpacing(20);

  grid->addWidget(buildTargetsCard(), 1);
  grid->addWidget(buildEngineCard(), 1);

  auto* rightCol = new QVBoxLayout();
  rightCol->setSpacing(20);
  rightCol->addWidget(buildSettingsCard());
  rightCol->addWidget(buildRecentScansCard(), 1);
  auto* rightWrap = new QWidget();
  rightWrap->setStyleSheet("background: transparent;");
  rightWrap->setLayout(rightCol);
  grid->addWidget(rightWrap, 1);

  main->addLayout(grid, 1);
  main->addStretch(1);

  scroll->setWidget(content);
}

// ============================================================================
//  Card builders
// ============================================================================
QFrame* ScanPage::buildTargetsCard() {
  auto* card = new QFrame();
  card->setObjectName("OdyScanCard");
  card->setAttribute(Qt::WA_StyledBackground, true);
  card->setStyleSheet(cardQss());

  auto* v = new QVBoxLayout(card);
  v->setContentsMargins(20, 20, 20, 20);
  v->setSpacing(16);

  auto* title = new QLabel("Scan Targets", card);
  title->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                           .arg(Theme::Color::textPrimary)
                           .arg(Theme::Type::qss(Theme::Type::H2, Theme::Type::WeightBold)));
  v->addWidget(title);

  auto* hint = new QLabel("Choose what you want to scan", card);
  hint->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                          .arg(Theme::Color::textSecondary)
                          .arg(Theme::Type::qss(Theme::Type::Caption)));
  v->addWidget(hint);

  // Drop area
  m_dropArea = new DropArea(card);
  connect(m_dropArea, &DropArea::filesDropped, this, &ScanPage::onTargetsDropped);
  v->addWidget(m_dropArea);

  // Buttons row
  auto* btnRow = new QHBoxLayout();
  btnRow->setSpacing(10);
  m_btnSelectFiles = new QPushButton("Select Files / Folders", card);
  m_btnSelectFiles->setCursor(Qt::PointingHandCursor);
  m_btnSelectFiles->setStyleSheet(primaryButtonQss());
  connect(m_btnSelectFiles, &QPushButton::clicked, this, &ScanPage::onSelectFiles);
  btnRow->addWidget(m_btnSelectFiles, 1);

  m_btnSelectDrive = new QPushButton("Select Drive", card);
  m_btnSelectDrive->setCursor(Qt::PointingHandCursor);
  m_btnSelectDrive->setStyleSheet(secondaryButtonQss());
  connect(m_btnSelectDrive, &QPushButton::clicked, this, &ScanPage::onSelectDrive);
  btnRow->addWidget(m_btnSelectDrive, 1);
  v->addLayout(btnRow);

  // Selected targets list
  m_targetsHeader = new QLabel("Selected Targets (0)", card);
  m_targetsHeader->setStyleSheet(
      QString("QLabel { color: %1; %2 background: transparent;"
              " padding-top: 6px; }")
          .arg(Theme::Color::textPrimary)
          .arg(Theme::Type::qss(Theme::Type::H3, Theme::Type::WeightSemi)));
  v->addWidget(m_targetsHeader);

  m_targetList = new QListWidget(card);
  m_targetList->setStyleSheet(
      QString("QListWidget { background-color: %1; color: %2;"
              " border: 1px solid %3; border-radius: 8px;"
              " padding: 6px; }"
              "QListWidget::item { padding: 8px; border-bottom: 1px solid %3; }"
              "QListWidget::item:hover { background-color: %4; }")
          .arg(
              Theme::Color::bgSecondary,
              Theme::Color::textPrimary,
              Theme::Color::borderSubtle,
              Theme::Color::bgCardHover));
  m_targetList->setMinimumHeight(120);
  v->addWidget(m_targetList, 1);

  // Footer row: Clear All + total size
  auto* footer = new QHBoxLayout();
  m_btnClearAll = new QPushButton("Clear All", card);
  m_btnClearAll->setCursor(Qt::PointingHandCursor);
  m_btnClearAll->setStyleSheet(secondaryButtonQss());
  connect(m_btnClearAll, &QPushButton::clicked, this, &ScanPage::onClearTargets);
  footer->addWidget(m_btnClearAll);
  footer->addStretch(1);

  m_totalSize = new QLabel("Total Size: 0 B", card);
  m_totalSize->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                                 .arg(Theme::Color::textSecondary)
                                 .arg(Theme::Type::qss(Theme::Type::Caption)));
  footer->addWidget(m_totalSize);
  v->addLayout(footer);

  return card;
}

QFrame* ScanPage::buildEngineCard() {
  auto* card = new QFrame();
  card->setObjectName("OdyScanCard");
  card->setAttribute(Qt::WA_StyledBackground, true);
  card->setStyleSheet(cardQss());

  auto* v = new QVBoxLayout(card);
  v->setContentsMargins(20, 20, 20, 20);
  v->setSpacing(14);

  auto* title = new QLabel("Scan Engine", card);
  title->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                           .arg(Theme::Color::textPrimary)
                           .arg(Theme::Type::qss(Theme::Type::H2, Theme::Type::WeightBold)));
  v->addWidget(title);

  auto* hint = new QLabel("AI model and analysis options", card);
  hint->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                          .arg(Theme::Color::textSecondary)
                          .arg(Theme::Type::qss(Theme::Type::Caption)));
  v->addWidget(hint);

  // ── AI Model section ───────────────────────────────────────────────
  auto* modelHeader = new QHBoxLayout();
  auto* modelLab = new QLabel("AI Model", card);
  modelLab->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                              .arg(Theme::Color::textPrimary)
                              .arg(Theme::Type::qss(Theme::Type::H3, Theme::Type::WeightSemi)));
  modelHeader->addWidget(modelLab);
  modelHeader->addStretch(1);

  m_modelStatus = new QLabel("Active", card);
  m_modelStatus->setAlignment(Qt::AlignCenter);
  m_modelStatus->setStyleSheet(
      QString("QLabel { color: %1; background: transparent;"
              " border: 1px solid %1; border-radius: 6px;"
              " padding: 2px 10px; %2 }")
          .arg(Theme::Color::severitySafe)
          .arg(Theme::Type::qss(Theme::Type::Caption, Theme::Type::WeightSemi)));
  modelHeader->addWidget(m_modelStatus);
  v->addLayout(modelHeader);

  m_aiModel = new QComboBox(card);
  m_aiModel->setStyleSheet(comboQss());
  m_aiModel->addItems(
      {"ONNX Anomaly Model v2", "EMBER LightGBM (PE specialist)", "Hash-only mode"});
  v->addWidget(m_aiModel);

  m_modelHelp = new QLabel("Optimized for anomaly detection", card);
  m_modelHelp->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                                 .arg(Theme::Color::textMuted)
                                 .arg(Theme::Type::qss(Theme::Type::Caption)));
  v->addWidget(m_modelHelp);

  // Subtle separator line
  auto* sep = new QFrame(card);
  sep->setFrameShape(QFrame::HLine);
  sep->setStyleSheet(QString("QFrame { background-color: %1; border: none; max-height: 1px; }")
                         .arg(Theme::Color::borderSubtle));
  v->addWidget(sep);

  // ── Detection Options ──────────────────────────────────────────────
  auto* detectLab = new QLabel("Detection Options", card);
  detectLab->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                               .arg(Theme::Color::textPrimary)
                               .arg(Theme::Type::qss(Theme::Type::H3, Theme::Type::WeightSemi)));
  v->addWidget(detectLab);

  auto buildOpt = [&](const QString& label, const QString& sub, bool defaultOn) -> QCheckBox* {
    auto* col = new QVBoxLayout();
    col->setContentsMargins(0, 0, 0, 0);
    col->setSpacing(2);

    auto* cb = new QCheckBox(label, card);
    cb->setChecked(defaultOn);
    cb->setStyleSheet(checkboxQss());
    col->addWidget(cb);

    auto* desc = new QLabel(sub, card);
    desc->setContentsMargins(28, 0, 0, 0);
    desc->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                            .arg(Theme::Color::textSecondary)
                            .arg(Theme::Type::qss(Theme::Type::Caption)));
    col->addWidget(desc);

    v->addLayout(col);
    return cb;
  };

  m_optRootkit =
      buildOpt("Rootkit Detection", "Scan for hidden rootkits and kernel-level threats", true);
  m_optMemory = buildOpt("Memory Analysis", "Analyze running processes and memory patterns", true);
  m_optHeuristic =
      buildOpt("Heuristic Analysis", "Use AI heuristics to detect unknown threats", true);

  // Separator
  auto* sep2 = new QFrame(card);
  sep2->setFrameShape(QFrame::HLine);
  sep2->setStyleSheet(QString("QFrame { background-color: %1; border: none; max-height: 1px; }")
                          .arg(Theme::Color::borderSubtle));
  v->addWidget(sep2);

  // ── Scan Depth ─────────────────────────────────────────────────────
  auto* depthLab = new QLabel("Scan Depth", card);
  depthLab->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                              .arg(Theme::Color::textPrimary)
                              .arg(Theme::Type::qss(Theme::Type::H3, Theme::Type::WeightSemi)));
  v->addWidget(depthLab);

  m_scanDepth = new QComboBox(card);
  m_scanDepth->setStyleSheet(comboQss());
  m_scanDepth->addItem("Quick Scan", Quick);
  m_scanDepth->addItem("Standard Scan", Standard);
  m_scanDepth->addItem("Deep Scan", Deep);
  m_scanDepth->setCurrentIndex(Standard);
  v->addWidget(m_scanDepth);

  m_depthHelp = new QLabel("Recommended for most systems", card);
  m_depthHelp->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                                 .arg(Theme::Color::textMuted)
                                 .arg(Theme::Type::qss(Theme::Type::Caption)));
  v->addWidget(m_depthHelp);

  v->addStretch(1);

  // ── Start Scan ─────────────────────────────────────────────────────
  m_btnStart = new QPushButton("Start Scan", card);
  m_btnStart->setCursor(Qt::PointingHandCursor);
  m_btnStart->setMinimumHeight(46);
  m_btnStart->setStyleSheet(primaryButtonQss());
  connect(m_btnStart, &QPushButton::clicked, this, &ScanPage::onStartScan);
  v->addWidget(m_btnStart);

  m_startSubtitle = new QLabel("This may take a few moments", card);
  m_startSubtitle->setAlignment(Qt::AlignCenter);
  m_startSubtitle->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                                     .arg(Theme::Color::textMuted)
                                     .arg(Theme::Type::qss(Theme::Type::Caption)));
  v->addWidget(m_startSubtitle);

  return card;
}

QFrame* ScanPage::buildSettingsCard() {
  auto* card = new QFrame();
  card->setObjectName("OdyScanCard");
  card->setAttribute(Qt::WA_StyledBackground, true);
  card->setStyleSheet(cardQss());

  auto* v = new QVBoxLayout(card);
  v->setContentsMargins(20, 18, 20, 18);
  v->setSpacing(12);

  auto* title = new QLabel("Scan Settings", card);
  title->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                           .arg(Theme::Color::textPrimary)
                           .arg(Theme::Type::qss(Theme::Type::H2, Theme::Type::WeightBold)));
  v->addWidget(title);

  auto buildKv = [&](const QString& label, const QString& value) {
    auto* row = new QHBoxLayout();
    auto* k = new QLabel(label, card);
    k->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                         .arg(Theme::Color::textSecondary)
                         .arg(Theme::Type::qss(Theme::Type::Body)));
    row->addWidget(k);
    row->addStretch(1);

    auto* val = new QLabel(value, card);
    val->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                           .arg(Theme::Color::textPrimary)
                           .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi)));
    row->addWidget(val);
    v->addLayout(row);
  };

  buildKv("Scan Timeout", "10 minutes");
  buildKv("Max File Size", "100 MB");
  buildKv("Excluded Paths", "3 paths");

  m_btnAdvanced = new QPushButton("Advanced Settings", card);
  m_btnAdvanced->setCursor(Qt::PointingHandCursor);
  m_btnAdvanced->setStyleSheet(secondaryButtonQss());
  connect(m_btnAdvanced, &QPushButton::clicked, this, &ScanPage::onAdvancedSettingsClicked);
  v->addWidget(m_btnAdvanced);

  return card;
}

QFrame* ScanPage::buildRecentScansCard() {
  auto* card = new QFrame();
  card->setObjectName("OdyScanCard");
  card->setAttribute(Qt::WA_StyledBackground, true);
  card->setStyleSheet(cardQss());

  auto* v = new QVBoxLayout(card);
  v->setContentsMargins(20, 18, 20, 18);
  v->setSpacing(12);

  auto* headerRow = new QHBoxLayout();
  auto* title = new QLabel("Recent Scans", card);
  title->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                           .arg(Theme::Color::textPrimary)
                           .arg(Theme::Type::qss(Theme::Type::H2, Theme::Type::WeightBold)));
  headerRow->addWidget(title);
  headerRow->addStretch(1);

  m_btnViewAll = new QPushButton("View All", card);
  m_btnViewAll->setCursor(Qt::PointingHandCursor);
  m_btnViewAll->setFlat(true);
  m_btnViewAll->setStyleSheet(
      QString("QPushButton { background: transparent; color: %1;"
              " border: none; padding: 4px 8px; %2 }"
              "QPushButton:hover { color: %3; }")
          .arg(Theme::Color::accentBlue)
          .arg(Theme::Type::qss(Theme::Type::Caption, Theme::Type::WeightSemi))
          .arg(Theme::Color::accentBlueHover));
  connect(m_btnViewAll, &QPushButton::clicked, this, &ScanPage::viewAllRecentRequested);
  headerRow->addWidget(m_btnViewAll);
  v->addLayout(headerRow);

  m_recentList = new QListWidget(card);
  m_recentList->setStyleSheet(QString("QListWidget { background: transparent;"
                                      " border: none; padding: 0; }"
                                      "QListWidget::item { padding: 6px 0;"
                                      " border-bottom: 1px solid %1; }")
                                  .arg(Theme::Color::borderSubtle));
  m_recentList->setSelectionMode(QAbstractItemView::NoSelection);
  m_recentList->setMinimumHeight(220);
  v->addWidget(m_recentList, 1);

  m_btnExport = new QPushButton("Export Scan Logs", card);
  m_btnExport->setCursor(Qt::PointingHandCursor);
  m_btnExport->setStyleSheet(secondaryButtonQss());
  connect(m_btnExport, &QPushButton::clicked, this, &ScanPage::exportLogsRequested);
  v->addWidget(m_btnExport);

  return card;
}

// ============================================================================
//  Slots
// ============================================================================
void ScanPage::onSelectFiles() {
  const QString home = QDir::homePath();
  const QStringList paths = QFileDialog::getOpenFileNames(this, "Select files to scan", home);
  if (!paths.isEmpty())
    onTargetsDropped(paths);
}

void ScanPage::onSelectDrive() {
  // On macOS this opens the Volumes picker; on Linux/Windows it shows a
  // standard directory chooser rooted at /Volumes or /mnt or C:\.
  const QString start =
#if defined(Q_OS_MACOS)
      "/Volumes";
#elif defined(Q_OS_WIN)
      "";
#else
      "/mnt";
#endif
  const QString dir = QFileDialog::getExistingDirectory(
      this, "Select drive or folder to scan", start, QFileDialog::ShowDirsOnly);
  if (!dir.isEmpty())
    onTargetsDropped({dir});
}

void ScanPage::onTargetsDropped(const QStringList& paths) {
  for (const QString& p : paths) {
    if (!m_targets.contains(p))
      m_targets.append(p);
  }
  rebuildTargetList();
}

void ScanPage::onClearTargets() {
  m_targets.clear();
  rebuildTargetList();
}

void ScanPage::onStartScan() {
  if (!m_btnStart || !m_btnStart->isEnabled())
    return;
  const int depth = m_scanDepth ? m_scanDepth->currentData().toInt() : Standard;
  emit scanRequested(m_targets, depth);
}

void ScanPage::onAdvancedSettingsClicked() {
  // Placeholder — Advanced settings dialog is future work. We leave
  // a hint in the log so the user knows the click registered.
  qInfo() << "[Scan] Advanced Settings — not yet implemented "
             "(use the Settings page for current toggles).";
}

// ============================================================================
//  List builders
// ============================================================================
void ScanPage::rebuildTargetList() {
  if (!m_targetList)
    return;
  m_targetList->clear();

  if (m_targets.isEmpty()) {
    auto* item = new QListWidgetItem(
        "No targets selected. Drag files in "
        "or use the buttons above.");
    item->setForeground(QColor(Theme::Color::textMuted));
    item->setFlags(Qt::ItemIsEnabled);
    m_targetList->addItem(item);
  } else {
    for (const QString& path : m_targets) {
      const QFileInfo fi(path);
      auto* row = new QWidget();
      row->setStyleSheet("background: transparent;");
      auto* h = new QHBoxLayout(row);
      h->setContentsMargins(8, 4, 8, 4);
      h->setSpacing(10);

      auto* iconLab = new QLabel(
          fi.isDir() ? QString::fromUtf8("\xE2\x96\xA4")   // ▤
                     : QString::fromUtf8("\xE2\x96\xA1"),  // □
          row);
      iconLab->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                                 .arg(Theme::Color::accentBlue)
                                 .arg(Theme::Type::qss(Theme::Type::Body)));
      h->addWidget(iconLab);

      auto* col = new QVBoxLayout();
      col->setSpacing(0);
      auto* nameLab = new QLabel(path, row);
      nameLab->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                                 .arg(Theme::Color::textPrimary)
                                 .arg(Theme::Type::qss(Theme::Type::Caption)));
      col->addWidget(nameLab);
      auto* typeLab = new QLabel(fi.isDir() ? "Folder" : "File", row);
      typeLab->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                                 .arg(Theme::Color::textMuted)
                                 .arg(Theme::Type::qss(Theme::Type::Tiny)));
      col->addWidget(typeLab);
      h->addLayout(col, 1);

      // Quick-size readout per row when computable cheaply.
      const qint64 sz = fi.isFile() ? fi.size() : 0;
      auto* sizeLab = new QLabel(fi.isFile() ? prettyBytes(sz) : "—", row);
      sizeLab->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                                 .arg(Theme::Color::textSecondary)
                                 .arg(Theme::Type::qss(Theme::Type::Caption)));
      h->addWidget(sizeLab, 0, Qt::AlignVCenter);

      auto* item = new QListWidgetItem(m_targetList);
      item->setSizeHint(row->sizeHint());
      m_targetList->setItemWidget(item, row);
    }
  }

  m_targetsHeader->setText(QString("Selected Targets (%1)").arg(m_targets.size()));
  m_totalSize->setText(QString("Total Size: %1").arg(prettyBytes(totalSelectedSize())));
}

void ScanPage::rebuildRecentScans() {
  if (!m_recentList)
    return;
  m_recentList->clear();

  if (m_history.isEmpty()) {
    auto* item = new QListWidgetItem("No scans yet.");
    item->setForeground(QColor(Theme::Color::textMuted));
    item->setFlags(Qt::ItemIsEnabled);
    m_recentList->addItem(item);
    return;
  }

  const int maxRows = qMin(6, m_history.size());
  for (int i = 0; i < maxRows; ++i) {
    const ScanRecord& r = m_history[i];
    const int totalThreats = r.criticalCount + r.suspiciousOnly + r.reviewCount;
    const bool clean = totalThreats == 0;

    auto* row = new QWidget();
    row->setStyleSheet("background: transparent;");
    auto* h = new QHBoxLayout(row);
    h->setContentsMargins(0, 6, 0, 6);
    h->setSpacing(12);

    // Status glyph (no emoji — text glyph)
    auto* glyph = new QLabel(
        clean ? QString::fromUtf8("\xE2\x9C\x93")   // ✓
              : QString::fromUtf8("\xE2\x9A\xA0"),  // ⚠
        row);
    glyph->setAlignment(Qt::AlignCenter);
    glyph->setFixedSize(28, 28);
    glyph->setStyleSheet(QString("QLabel { color: %1; background-color: %2;"
                                 " border-radius: 8px; %3 }")
                             .arg(clean ? Theme::Color::severitySafe : Theme::Color::severityMedium)
                             .arg(Theme::Color::bgSecondary)
                             .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightBold)));
    h->addWidget(glyph);

    auto* col = new QVBoxLayout();
    col->setSpacing(2);
    auto* tsLab = new QLabel(r.timestamp.toString("MMM d, yyyy hh:mm:ss"), row);
    tsLab->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                             .arg(Theme::Color::textPrimary)
                             .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi)));
    col->addWidget(tsLab);

    auto* typLab = new QLabel("Standard Scan", row);
    typLab->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                              .arg(Theme::Color::textSecondary)
                              .arg(Theme::Type::qss(Theme::Type::Caption)));
    col->addWidget(typLab);
    h->addLayout(col, 1);

    auto* statsCol = new QVBoxLayout();
    statsCol->setAlignment(Qt::AlignRight);
    statsCol->setSpacing(2);

    auto* filesLab = new QLabel(QString("%L1 files").arg(r.totalScanned), row);
    filesLab->setAlignment(Qt::AlignRight);
    filesLab->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                                .arg(Theme::Color::textSecondary)
                                .arg(Theme::Type::qss(Theme::Type::Caption)));
    statsCol->addWidget(filesLab);

    auto* threatLab = new QLabel(
        clean ? "No threats"
              : QString("%1 threat%2 found").arg(totalThreats).arg(totalThreats == 1 ? "" : "s"),
        row);
    threatLab->setAlignment(Qt::AlignRight);
    threatLab->setStyleSheet(
        QString("QLabel { color: %1; %2 background: transparent; }")
            .arg(clean ? Theme::Color::severitySafe : Theme::Color::severityCritical)
            .arg(Theme::Type::qss(Theme::Type::Caption, Theme::Type::WeightSemi)));
    statsCol->addWidget(threatLab);

    h->addLayout(statsCol, 0);

    auto* item = new QListWidgetItem(m_recentList);
    item->setSizeHint(row->sizeHint());
    m_recentList->setItemWidget(item, row);
  }
}

// ============================================================================
//  Public API used by MainWindow
// ============================================================================
void ScanPage::setStats(
    const QDateTime& lastScan,
    int filesScanned,
    int threatsFound,
    bool protectedNow,
    bool scanning) {
  if (m_kpiLastScan) {
    if (lastScan.isValid()) {
      m_kpiLastScan->setValue(lastScan.toString("MMM d, yyyy"));
      m_kpiLastScan->setSubtitle(lastScan.toString("hh:mm:ss"));
    } else {
      m_kpiLastScan->setValue("—");
      m_kpiLastScan->setSubtitle("No scans yet");
    }
  }

  if (m_kpiFilesScanned) {
    m_kpiFilesScanned->setValue(QString("%L1").arg(filesScanned));
    m_kpiFilesScanned->setSubtitle("Total files");
  }

  if (m_kpiThreatsFound) {
    m_kpiThreatsFound->setValue(QString::number(threatsFound));
    m_kpiThreatsFound->setSubtitle(threatsFound > 0 ? "Requires attention" : "No threats detected");
  }

  if (m_kpiStatus) {
    if (scanning) {
      m_kpiStatus->setTone(StatCard::Info);
      m_kpiStatus->setValue("Scanning");
      m_kpiStatus->setSubtitle("Scan in progress");
    } else if (!protectedNow) {
      m_kpiStatus->setTone(StatCard::Critical);
      m_kpiStatus->setValue("At Risk");
      m_kpiStatus->setSubtitle("Threats detected");
    } else {
      m_kpiStatus->setTone(StatCard::Safe);
      m_kpiStatus->setValue("Ready");
      m_kpiStatus->setSubtitle("System protected");
    }
  }

  setScanning(scanning);
}

void ScanPage::setRecentScans(const QVector<ScanRecord>& history) {
  m_history = history;
  rebuildRecentScans();
}

void ScanPage::setScanning(bool scanning) {
  if (m_btnStart) {
    m_btnStart->setEnabled(!scanning);
    m_btnStart->setText(scanning ? "Scan in progress…" : "Start Scan");
  }
  if (m_startSubtitle)
    m_startSubtitle->setText(
        scanning ? "Findings will appear under Results" : "This may take a few moments");

  // ── Progress strip lifecycle ──────────────────────────────────────
  if (!m_progressStrip) return;

  if (scanning) {
    // Make the strip visible (first scan) and reset the indicator state
    // for a fresh run. We track wall-clock so the elapsed timer is robust
    // to QTimer drift over long scans.
    m_progressStrip->setVisible(true);
    m_scanStarted = QDateTime::currentDateTime();
    if (m_progressBar)   { m_progressBar->setValue(0); }
    if (m_progressPct)   { m_progressPct->setText("0%"); }
    if (m_progressPhase) { m_progressPhase->setText("Scanning…"); }
    if (m_elapsedLabel)  { m_elapsedLabel->setText("Elapsed: 00:00"); }
    if (m_elapsedTimer && !m_elapsedTimer->isActive())
      m_elapsedTimer->start();
  } else {
    // Scan ended — leave the strip visible so the user sees the final
    // state. Stop the ticker and pin progress to 100%.
    if (m_elapsedTimer && m_elapsedTimer->isActive())
      m_elapsedTimer->stop();
    if (m_progressBar)   { m_progressBar->setValue(100); }
    if (m_progressPct)   { m_progressPct->setText("100%"); }
    if (m_progressPhase) { m_progressPhase->setText("Scan Complete"); }
  }
}

// UI-only forwarders — backend signals stay unchanged.
void ScanPage::setProgress(int percent) {
  percent = qBound(0, percent, 100);
  if (m_progressBar && percent > m_progressBar->value())
    m_progressBar->setValue(percent);
  if (m_progressPct)
    m_progressPct->setText(QString::number(percent) + "%");
}

void ScanPage::setLiveCounts(int filesScanned, int threatsFound) {
  if (m_kpiFilesScanned) {
    if (filesScanned > 0) {
      m_kpiFilesScanned->setValue(QString("%L1").arg(filesScanned));
      m_kpiFilesScanned->setSubtitle("Files scanned so far");
    } else {
      // Backend doesn't expose a fine-grained running count yet; leave
      // value at the previous total but reflect the in-progress state.
      m_kpiFilesScanned->setSubtitle("Counting…");
    }
  }
  if (m_kpiThreatsFound) {
    m_kpiThreatsFound->setValue(QString::number(threatsFound));
    m_kpiThreatsFound->setSubtitle(
        threatsFound > 0 ? "Found during this scan" : "None so far");
  }
}

// ============================================================================
//  Helpers
// ============================================================================
qint64 ScanPage::totalSelectedSize() const {
  qint64 total = 0;
  for (const QString& path : m_targets) {
    const QFileInfo fi(path);
    if (fi.isFile()) {
      total += fi.size();
    } else if (fi.isDir()) {
      // Cheap directory size: 1-level QDirIterator. We deliberately
      // don't descend recursively because it can stall the UI on
      // large trees (~100k files). The user will see the actual
      // bytes scanned in the dashboard once the scan kicks off.
      QDirIterator it(path, QDir::Files);
      while (it.hasNext()) {
        it.next();
        total += it.fileInfo().size();
      }
    }
  }
  return total;
}

QString ScanPage::prettyBytes(qint64 b) {
  if (b >= 1LL << 30)
    return QString("%1 GB").arg(b / double(1LL << 30), 0, 'f', 1);
  if (b >= 1LL << 20)
    return QString("%1 MB").arg(b / double(1LL << 20), 0, 'f', 1);
  if (b >= 1LL << 10)
    return QString("%1 KB").arg(b / double(1LL << 10), 0, 'f', 1);
  return QString("%1 B").arg(b);
}
