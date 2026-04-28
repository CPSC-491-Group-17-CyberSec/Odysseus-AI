#pragma once
// ============================================================================
// ActivityList.h  –  Recent Activity card for the dashboard
//
// Each entry has:
//   • severity-colored icon ( ! / ⚠ / ⓘ / ✓ )
//   • title (Critical threat detected: ransomware.exe)
//   • subtitle (path or detail)
//   • relative timestamp (2 min ago)
//
// Plain value type so MainWindow can build entries from m_findings,
// ScanRecord history, and rootkit events with a few lines each.
// ============================================================================

#include <QFrame>
#include <QString>
#include <QDateTime>
#include <QVector>

class QListWidget;

class ActivityList : public QFrame
{
    Q_OBJECT
public:
    /// Visual + semantic tone of an activity row.
    /// Each tone maps to a distinct icon + leading-dot color:
    ///   Critical → red ❗   threat detected
    ///   Warning  → amber ⚠  suspicious file / process
    ///   Info     → blue ⓘ  scan completed / general
    ///   Success  → green ✓  scan clean / system protected
    ///   System   → purple ◎ system-monitoring event (refresh, integrity)
    enum Tone { Critical, Warning, Info, Success, System };

    struct Entry {
        Tone     tone = Info;
        QString  title;
        QString  subtitle;
        QDateTime when;
    };

    explicit ActivityList(QWidget* parent = nullptr);

    void setEntries(const QVector<Entry>& entries);
    void clearEntries();

signals:
    void viewAllClicked();

private:
    QListWidget* m_list = nullptr;
};
