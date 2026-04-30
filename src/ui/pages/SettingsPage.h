#pragma once
// ============================================================================
// SettingsPage.h  –  Step 4: Scanner-config toggles bound to ScannerConfig.
//
// Reads ScannerConfigStore::current() on construction and on every page
// re-entry. Tracks dirty state — Save button stays disabled until the user
// actually changes something, then writes back via ScannerConfigStore::set().
// Reset button rolls back to factory defaults via ::resetToDefaults().
// ============================================================================

#include <QWidget>
#include <QMessageBox>

class ToggleRow;
class QPushButton;
class QLabel;
class QListWidget;

class SettingsPage : public QWidget
{
    Q_OBJECT
public:
    explicit SettingsPage(QWidget* parent = nullptr);
    bool clearAllData();

    /// Re-read every toggle from the live ScannerConfig. Call after
    /// programmatic config changes (e.g. user edited the JSON file
    /// externally) or whenever the page becomes visible again.
    void reloadFromConfig();

signals:
    /// Emitted after a successful Save.
    void configSaved();
    void clearCacheRequested();

private slots:
    void onSaveClicked();
    void onResetClicked();
    void markDirty(bool /*ignored*/);
    void onClearCacheClicked();

    // Phase 5 — Allowlist editor (lives in this page so we don't add
    // a whole new sidebar entry just for the list).
    void onAllowlistRefreshClicked();
    void onAllowlistRemoveClicked();
    void onAllowlistSelectionChanged();

private:
    void rebuildAllowlistView();
    void setAllowlistStatus(const QString& msg, bool isError);

private:
    void buildUi();
    void applyDirtyState();

    // ── Detection Engine ───────────────────────────────────────────────
    ToggleRow*  m_yara              = nullptr;
    ToggleRow*  m_reputationUpsert  = nullptr;
    ToggleRow*  m_codeSigning       = nullptr;
    ToggleRow*  m_experimentalRules = nullptr;

    // ── System Monitoring ──────────────────────────────────────────────
    ToggleRow*  m_systemMonitoring  = nullptr;
    ToggleRow*  m_processScan       = nullptr;
    ToggleRow*  m_persistenceScan   = nullptr;
    ToggleRow*  m_processHeuristics = nullptr;

    // ── Rootkit Awareness ──────────────────────────────────────────────
    ToggleRow*  m_rootkit           = nullptr;
    ToggleRow*  m_crossView         = nullptr;
    ToggleRow*  m_kextCheck         = nullptr;
    ToggleRow*  m_integrity         = nullptr;

    // ── Diagnostics ────────────────────────────────────────────────────
    ToggleRow*  m_verboseLogging    = nullptr;

    // ── EDR-Lite Monitoring (Beta) — Phase 4 ───────────────────────────
    ToggleRow*  m_edrEnabled              = nullptr;
    class QComboBox* m_edrInterval        = nullptr;
    ToggleRow*  m_edrAlertNewProcess      = nullptr;
    ToggleRow*  m_edrAlertNewPersistence  = nullptr;
    ToggleRow*  m_edrAlertIntegrity       = nullptr;
    ToggleRow*  m_edrAlertKernelExt       = nullptr;

    // ── Allowlist Editor — Phase 5 ─────────────────────────────────────
    QListWidget* m_allowlistView   = nullptr;
    QPushButton* m_allowlistRemove = nullptr;
    QPushButton* m_allowlistRefresh = nullptr;
    QLabel*      m_allowlistStatus = nullptr;
    QLabel*      m_allowlistEmpty  = nullptr;

    // ── Footer ─────────────────────────────────────────────────────────
    QPushButton* m_saveBtn   = nullptr;
    QPushButton* m_resetBtn  = nullptr;
    QLabel*      m_pathLabel = nullptr;
    QLabel*      m_status    = nullptr;

    bool m_dirty = false;
};
