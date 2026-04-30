#pragma once
// ============================================================================
// QuarantinePage.h  –  Phase 5 follow-up: list + restore quarantined files.
//
// Surfaces the existing odysseus::response::Quarantine backend in the UI.
// Read-only listing + a Restore action per row. No delete (Phase 5 forbids
// non-reversible destructive actions on quarantined items).
//
// Source of truth:
//   • odysseus::response::globalResponseManager().quarantine().list()
//   • odysseus::response::globalResponseManager().execute(RestoreFromQuarantine)
//
// This page does no I/O of its own — every backend call is routed through
// the singleton manager so the action log captures restores too.
// ============================================================================

#include <QWidget>

class QListWidget;
class QListWidgetItem;
class QLabel;
class QPushButton;

class QuarantinePage : public QWidget
{
    Q_OBJECT
public:
    explicit QuarantinePage(QWidget* parent = nullptr);

    /// Reload the list from Quarantine::list(). Cheap; the metadata is
    /// already in memory inside the Quarantine instance.
    void refresh();

private slots:
    void onSelectionChanged();
    void onRestoreClicked();
    void onRefreshClicked();

private:
    void buildUi();
    void setStatus(const QString& msg, bool isError);

    QListWidget*  m_list      = nullptr;
    QLabel*       m_detail    = nullptr;
    QLabel*       m_status    = nullptr;
    QPushButton*  m_restoreBtn = nullptr;
    QPushButton*  m_refreshBtn = nullptr;
    QLabel*       m_emptyHint = nullptr;
};
