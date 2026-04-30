// ============================================================================
// SettingsPage.cpp
//
// Layout:
//   ┌─ Settings ─────────────────────────────────────────────┐
//   │ Configure scanner behavior. Changes take effect on    │
//   │ the next scan.                                          │
//   │                                                          │
//   │ ┌─ Detection Engine ────────────────────────────────┐ │
//   │ │ YARA Scanning             [SWITCH]                │ │
//   │ │ Reputation Auto-Upsert    [SWITCH]                │ │
//   │ │ ...                                                 │ │
//   │ └────────────────────────────────────────────────────┘ │
//   │ ┌─ System Monitoring ───────────────────────────────┐ │
//   │ │ ...                                                 │ │
//   │ └────────────────────────────────────────────────────┘ │
//   │ ┌─ Rootkit Awareness ───────────────────────────────┐ │
//   │ │ ...                                                 │ │
//   │ └────────────────────────────────────────────────────┘ │
//   │ ┌─ Diagnostics ─────────────────────────────────────┐ │
//   │ │ ...                                                 │ │
//   │ └────────────────────────────────────────────────────┘ │
//   │                                                          │
//   │ Config file: /Users/.../odysseus_config.json           │
//   │ [Reset to Defaults]              [Save Changes]        │
//   └────────────────────────────────────────────────────────┘
// ============================================================================

#include "SettingsPage.h"
#include "../theme/DashboardTheme.h"
#include "../widgets/ToggleRow.h"
#include "../../../include/core/ScannerConfig.h"

#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QFrame>
#include <QFileInfo>
#include <QMessageBox>
#include <QTimer>
#include <QApplication>
#include <QPainter>
#include <QStyleOption>
// #include <QStandardPaths>

class CacheOverlay : public QWidget {
public:
    CacheOverlay(QWidget* parent, std::function<void()> onConfirm) : QWidget(parent) {
        resize(parent->size()); // Cover the whole page
        
        // Semi-transparent dark background
        setStyleSheet("CacheOverlay { background-color: rgba(0, 0, 0, 180); }");
        
        // The inner dialog box
        QFrame* dialog = new QFrame(this);
        dialog->setStyleSheet("QFrame { background-color: #1E1E1E; border-radius: 8px; border: 1px solid #333333; }");
        dialog->setFixedSize(400, 180);
        
        QVBoxLayout* lay = new QVBoxLayout(dialog);
        lay->setContentsMargins(24, 24, 24, 24);
        lay->setSpacing(12);
        
        QLabel* title = new QLabel("Clear Cache", dialog);
        title->setStyleSheet("color: #FFFFFF; font-size: 18px; font-weight: bold; background: transparent; border: none;");
        
        QLabel* desc = new QLabel("Are you sure you want to clear the cache?\n\nThis action cannot be undone.", dialog);
        desc->setStyleSheet("color: #A0A0A0; font-size: 14px; background: transparent; border: none;");
        desc->setWordWrap(true);
        
        QHBoxLayout* btnLay = new QHBoxLayout();
        
        QPushButton* cancelBtn = new QPushButton("Cancel", dialog);
        cancelBtn->setCursor(Qt::PointingHandCursor);
        cancelBtn->setStyleSheet("QPushButton { background-color: #333333; color: white; padding: 8px 16px; border-radius: 4px; font-weight: bold; } QPushButton:hover { background-color: #444444; }");
        
        QPushButton* yesBtn = new QPushButton("Clear Cache", dialog);
        yesBtn->setCursor(Qt::PointingHandCursor);
        yesBtn->setStyleSheet("QPushButton { background-color: #D32F2F; color: white; padding: 8px 16px; border-radius: 4px; font-weight: bold; } QPushButton:hover { background-color: #F44336; }");
        
        btnLay->addStretch();
        btnLay->addWidget(cancelBtn);
        btnLay->addWidget(yesBtn);
        
        lay->addWidget(title);
        lay->addWidget(desc);
        lay->addStretch();
        lay->addLayout(btnLay);
        
        // Destroy overlay on cancel
        connect(cancelBtn, &QPushButton::clicked, this, &QWidget::deleteLater);
        
        // Execute lambda and destroy overlay on confirm
        connect(yesBtn, &QPushButton::clicked, this, [this, onConfirm]() {
            onConfirm();
            this->deleteLater();
        });
    }

protected:
    // Required to render background colors properly on custom QWidgets
    void paintEvent(QPaintEvent* event) override {
        QStyleOption opt;
        opt.initFrom(this);
        QPainter p(this);
        style()->drawPrimitive(QStyle::PE_Widget, &opt, &p, this);
    }
    
    // Ensure the overlay and box stay centered if the user resizes the app
    void resizeEvent(QResizeEvent* event) override {
        if (parentWidget()) resize(parentWidget()->size());
        QFrame* dialog = findChild<QFrame*>();
        if (dialog) {
            dialog->move((width() - dialog->width()) / 2, (height() - dialog->height()) / 2);
        }
    }
};

namespace {

// Reusable section-card helper. Returns a card frame + an inner vlayout
// the caller pushes ToggleRows into.
QFrame* makeSectionCard(const QString& title,
                         QWidget*       parent,
                         QVBoxLayout**  innerLayoutOut)
{
    auto* card = new QFrame(parent);
    card->setObjectName("OdySettingsSection");
    card->setAttribute(Qt::WA_StyledBackground, true);
    card->setStyleSheet(QString(
        "QFrame#OdySettingsSection {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: %3px;"
        "}"
    ).arg(Theme::Color::bgCard, Theme::Color::borderSubtle)
     .arg(Theme::Size::cardRadius));

    auto* v = new QVBoxLayout(card);
    v->setContentsMargins(20, 16, 20, 12);
    v->setSpacing(0);

    auto* header = new QLabel(title, card);
    header->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent;"
        " padding-bottom: 6px; }")
            .arg(Theme::Color::textPrimary)
            .arg(Theme::Type::qss(Theme::Type::H2, Theme::Type::WeightBold)));
    v->addWidget(header);

    // Subtle divider under the section title
    auto* div = new QFrame(card);
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet(QString("background-color: %1; border: none;"
                                " max-height: 1px;")
                          .arg(Theme::Color::borderSubtle));
    v->addWidget(div);

    *innerLayoutOut = v;
    return card;
}

void appendToggle(QVBoxLayout* layout, ToggleRow* row)
{
    layout->addWidget(row);
}

}  // anonymous

// ============================================================================
// Construction
// ============================================================================
SettingsPage::SettingsPage(QWidget* parent)
    : QWidget(parent)
{
    setStyleSheet(QString("background-color: %1;").arg(Theme::Color::bgPrimary));
    buildUi();
    reloadFromConfig();
}

void SettingsPage::buildUi()
{
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
    auto* title = new QLabel("Settings", content);
    title->setStyleSheet(QString("color: %1; %2")
                              .arg(Theme::Color::textPrimary)
                              .arg(Theme::Type::qss(Theme::Type::Display,
                                                      Theme::Type::WeightBold)));
    main->addWidget(title);

    auto* sub = new QLabel(
        "Configure scanner behavior. Changes take effect on the next scan.",
        content);
    sub->setStyleSheet(QString("color: %1; %2")
                            .arg(Theme::Color::textSecondary)
                            .arg(Theme::Type::qss(Theme::Type::Body)));
    main->addWidget(sub);

    // ── Section: Detection Engine ──────────────────────────────────────
    {
        QVBoxLayout* sec = nullptr;
        main->addWidget(makeSectionCard("Detection Engine", content, &sec));
        m_yara = new ToggleRow("YARA Scanning",
            "Use libyara rules as a third detection pass alongside hash and AI.");
        m_reputationUpsert = new ToggleRow("Reputation Auto-Upsert",
            "Persist new YARA / AI flagged hashes for future scans.");
        m_codeSigning = new ToggleRow("Code Signing Checks",
            "Verify codesign / package ownership for flagged files (~30–80 ms each).");
        m_experimentalRules = new ToggleRow("Experimental YARA Rules",
            "Load aggressive heuristic rules. Higher false-positive rate.");
        appendToggle(sec, m_yara);
        appendToggle(sec, m_reputationUpsert);
        appendToggle(sec, m_codeSigning);
        appendToggle(sec, m_experimentalRules);
    }

    // ── Section: System Monitoring ─────────────────────────────────────
    {
        QVBoxLayout* sec = nullptr;
        main->addWidget(makeSectionCard("System Monitoring", content, &sec));
        m_systemMonitoring = new ToggleRow("System Monitoring (master)",
            "Top-level switch — disables all probes below if off.");
        m_processScan = new ToggleRow("Process Enumeration",
            "List running processes via sysctl on macOS, /proc on Linux.");
        m_persistenceScan = new ToggleRow("Persistence Scanning",
            "Walk LaunchAgents, LaunchDaemons, cron, and systemd unit files.");
        m_processHeuristics = new ToggleRow("Suspicious Process Heuristics",
            "Flag processes by exe path, name patterns, command-line indicators.");
        appendToggle(sec, m_systemMonitoring);
        appendToggle(sec, m_processScan);
        appendToggle(sec, m_persistenceScan);
        appendToggle(sec, m_processHeuristics);
    }

    // ── Section: Rootkit Awareness ─────────────────────────────────────
    {
        QVBoxLayout* sec = nullptr;
        main->addWidget(makeSectionCard("Rootkit Awareness", content, &sec));
        m_rootkit = new ToggleRow("Rootkit Awareness (master)",
            "Top-level switch — disables all rootkit checks below if off.");
        m_crossView = new ToggleRow("Process Cross-View",
            "Compare sysctl process list against `ps` output to spot lazy hooks.");
        m_kextCheck = new ToggleRow("Kernel / System Extensions",
            "Enumerate via systemextensionsctl + kmutil and flag non-Apple modules.");
        m_integrity = new ToggleRow("Integrity Baseline",
            "SHA-256 baseline of critical system binaries. Auto-rebases on OS update.");
        appendToggle(sec, m_rootkit);
        appendToggle(sec, m_crossView);
        appendToggle(sec, m_kextCheck);
        appendToggle(sec, m_integrity);
    }

    // ── Section: Diagnostics ───────────────────────────────────────────
    {
        QVBoxLayout* sec = nullptr;
        main->addWidget(makeSectionCard("Diagnostics", content, &sec));
        m_verboseLogging = new ToggleRow("Verbose Logging",
            "Detailed per-file pipeline traces. Noisy on real scans — turn on for debugging.");
        appendToggle(sec, m_verboseLogging);
    }

    // ── Data & Storage ─────────────────────────────────────────────────
    {
        QVBoxLayout* sec = nullptr;
        // Use your app's native card builder so the header perfectly matches the others
        main->addWidget(makeSectionCard("Data & Storage", content, &sec));

        QPushButton* clearCacheBtn = new QPushButton("Clear Cache", content);
        clearCacheBtn->setCursor(Qt::PointingHandCursor);
        
        // Style it to match your other outline buttons, turning red on hover
        clearCacheBtn->setStyleSheet(QString(
            "QPushButton {"
            "  background: transparent; color: %1;"
            "  border: 1px solid %2; border-radius: 8px;"
            "  padding: 8px 16px; margin-bottom: 8px; %3"
            "}"
            "QPushButton:hover { background-color: %4; color: white; border-color: %4; }"
        ).arg(Theme::Color::textSecondary,
              Theme::Color::borderSubtle,
              Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi),
              Theme::Color::severityCritical));

        connect(clearCacheBtn, &QPushButton::clicked, this, &SettingsPage::onClearCacheClicked);

        // Wrap the button in an HBoxLayout so it aligns left and doesn't stretch 100% width
        QHBoxLayout* btnLay = new QHBoxLayout();
        btnLay->addWidget(clearCacheBtn);
        btnLay->addStretch();

        sec->addLayout(btnLay);
    }

    // ── Footer: config path + actions ──────────────────────────────────
    auto* footer = new QFrame(content);
    footer->setStyleSheet(QString(
        "QFrame { background: transparent;"
        "         border-top: 1px solid %1;"
        "         padding-top: 12px; }")
            .arg(Theme::Color::borderSubtle));
    auto* footerLayout = new QVBoxLayout(footer);
    footerLayout->setContentsMargins(0, 12, 0, 0);
    footerLayout->setSpacing(10);

    m_pathLabel = new QLabel("", footer);
    m_pathLabel->setStyleSheet(QString(
        "color: %1; %2 background: transparent;")
            .arg(Theme::Color::textMuted)
            .arg(Theme::Type::qss(Theme::Type::Caption)));
    m_pathLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    footerLayout->addWidget(m_pathLabel);

    auto* actions = new QHBoxLayout();
    actions->setSpacing(10);

    m_resetBtn = new QPushButton("Reset to Defaults", footer);
    m_resetBtn->setCursor(Qt::PointingHandCursor);
    m_resetBtn->setStyleSheet(QString(
        "QPushButton {"
        "  background: transparent; color: %1;"
        "  border: 1px solid %2; border-radius: 8px;"
        "  padding: 8px 16px; %3"
        "}"
        "QPushButton:hover { background-color: %4; color: white; }"
    ).arg(Theme::Color::textSecondary,
          Theme::Color::borderSubtle,
          Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi),
          Theme::Color::severityCritical));
    actions->addWidget(m_resetBtn);

    m_status = new QLabel("", footer);
    m_status->setAlignment(Qt::AlignCenter);
    m_status->setStyleSheet(QString(
        "QLabel { color: %1; %2 background: transparent; }")
            .arg(Theme::Color::severitySafe)
            .arg(Theme::Type::qss(Theme::Type::Caption,
                                    Theme::Type::WeightSemi)));
    actions->addWidget(m_status, 1);

    m_saveBtn = new QPushButton("Save Changes", footer);
    m_saveBtn->setCursor(Qt::PointingHandCursor);
    m_saveBtn->setEnabled(false);     // disabled until something changes
    m_saveBtn->setStyleSheet(QString(
        "QPushButton {"
        "  background-color: %1; color: white; border: none;"
        "  border-radius: 8px; padding: 8px 18px; %2"
        "}"
        "QPushButton:hover  { background-color: %3; }"
        "QPushButton:disabled { background-color: %4; color: %5; }"
    )
    .arg(Theme::Color::accentBlue)
    .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightBold))
    .arg(Theme::Color::accentBlueHover)
    .arg(Theme::Color::bgCard)
    .arg(Theme::Color::textMuted));
    actions->addWidget(m_saveBtn);

    footerLayout->addLayout(actions);
    main->addWidget(footer);

    main->addStretch(1);
    scroll->setWidget(content);

    // Wire dirty-tracking on every toggle.
    QList<ToggleRow*> all = {
        m_yara, m_reputationUpsert, m_codeSigning, m_experimentalRules,
        m_systemMonitoring, m_processScan, m_persistenceScan, m_processHeuristics,
        m_rootkit, m_crossView, m_kextCheck, m_integrity,
        m_verboseLogging,
    };
    for (ToggleRow* r : all)
        connect(r, &ToggleRow::toggled, this, &SettingsPage::markDirty);

    connect(m_saveBtn,  &QPushButton::clicked,
            this,        &SettingsPage::onSaveClicked);
    connect(m_resetBtn, &QPushButton::clicked,
            this,        &SettingsPage::onResetClicked);
}

// ============================================================================
// Config <-> UI plumbing
// ============================================================================
void SettingsPage::reloadFromConfig()
{
    const ScannerConfig& cfg = ScannerConfigStore::current();

    m_yara             ->setChecked(cfg.yaraEnabled);
    m_reputationUpsert ->setChecked(cfg.reputationAutoUpsert);
    m_codeSigning      ->setChecked(cfg.codeSigningEnabled);
    m_experimentalRules->setChecked(cfg.experimentalRules);

    m_systemMonitoring ->setChecked(cfg.systemMonitoringEnabled);
    m_processScan      ->setChecked(cfg.processScanEnabled);
    m_persistenceScan  ->setChecked(cfg.persistenceScanEnabled);
    m_processHeuristics->setChecked(cfg.suspiciousProcessHeuristicsEnabled);

    m_rootkit          ->setChecked(cfg.rootkitAwarenessEnabled);
    m_crossView        ->setChecked(cfg.processCrossViewCheckEnabled);
    m_kextCheck        ->setChecked(cfg.kernelExtensionCheckEnabled);
    m_integrity        ->setChecked(cfg.integrityCheckEnabled);

    m_verboseLogging   ->setChecked(cfg.verboseLogging);

    m_pathLabel->setText(QString("Config file: %1").arg(ScannerConfigStore::configPath()));

    m_dirty = false;
    applyDirtyState();
    m_status->setText("");
}

void SettingsPage::markDirty(bool /*newValue*/)
{
    m_dirty = true;
    applyDirtyState();
    m_status->setText("");      // clear "Saved" toast on subsequent edits
}

void SettingsPage::applyDirtyState()
{
    m_saveBtn->setEnabled(m_dirty);
    m_saveBtn->setText(m_dirty ? "Save Changes" : "Saved");
}

void SettingsPage::onSaveClicked()
{
    ScannerConfig c;
    c.yaraEnabled                       = m_yara->isChecked();
    c.reputationAutoUpsert              = m_reputationUpsert->isChecked();
    c.codeSigningEnabled                = m_codeSigning->isChecked();
    c.experimentalRules                 = m_experimentalRules->isChecked();

    c.systemMonitoringEnabled           = m_systemMonitoring->isChecked();
    c.processScanEnabled                = m_processScan->isChecked();
    c.persistenceScanEnabled            = m_persistenceScan->isChecked();
    c.suspiciousProcessHeuristicsEnabled = m_processHeuristics->isChecked();

    c.rootkitAwarenessEnabled           = m_rootkit->isChecked();
    c.processCrossViewCheckEnabled      = m_crossView->isChecked();
    c.kernelExtensionCheckEnabled       = m_kextCheck->isChecked();
    c.integrityCheckEnabled             = m_integrity->isChecked();

    c.verboseLogging                    = m_verboseLogging->isChecked();

    // Preserve fields the page doesn't expose (experimentalSubdir,
    // maxCompileErrors).
    const ScannerConfig prev = ScannerConfigStore::current();
    c.experimentalSubdir = prev.experimentalSubdir;
    c.maxCompileErrors   = prev.maxCompileErrors;

    if (ScannerConfigStore::set(c)) {
        m_dirty = false;
        applyDirtyState();
        m_status->setText(QString::fromUtf8("\xE2\x9C\x93 Saved"));
        // Auto-clear the "Saved" toast after a couple of seconds.
        QTimer::singleShot(2500, this, [this]() {
            if (!m_dirty) m_status->setText("");
        });
        emit configSaved();
    } else {
        m_status->setStyleSheet(QString(
            "QLabel { color: %1; %2 background: transparent; }")
                .arg(Theme::Color::severityCritical)
                .arg(Theme::Type::qss(Theme::Type::Caption,
                                        Theme::Type::WeightSemi)));
        m_status->setText("Save failed — check log");
    }
}

void SettingsPage::onResetClicked()
{
    QMessageBox box(this);
    box.setWindowTitle("Reset to defaults?");
    box.setText("Reset all scanner-config toggles to their factory defaults?");
    box.setInformativeText("This is the same as deleting odysseus_config.json. "
                            "It cannot be undone.");
    box.setStandardButtons(QMessageBox::Cancel | QMessageBox::Reset);
    box.setDefaultButton(QMessageBox::Cancel);
    box.setIcon(QMessageBox::Warning);
    if (box.exec() != QMessageBox::Reset) return;

    ScannerConfigStore::resetToDefaults();
    reloadFromConfig();
    m_status->setText("Reset to defaults");
    QTimer::singleShot(2500, this, [this]() {
        if (!m_dirty) m_status->setText("");
    });
}

void SettingsPage::onClearCacheClicked()
{
    // QString roaming = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    // QString local = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    
    // QMessageBox::information(this, "Database Finder", 
    //     "Your active database is inside one of these folders:\n\n"
    //     "ROAMING:\n" + roaming + "\n\n"
    //     "LOCAL:\n" + local);

    CacheOverlay* overlay = new CacheOverlay(this, [this]() {
        emit clearCacheRequested();
        
        m_status->setStyleSheet(QString("QLabel { color: %1; background: transparent; }")
                                .arg(Theme::Color::severityLow));
        m_status->setText(QString::fromUtf8("\xE2\x9C\x93 Cache cleared"));
    });
    
    overlay->show();
}