#pragma once
// ============================================================================
// ThreatRow.h  –  Results-page row component.
//
// Layout (matches the strict mockup):
//   ●  THREAT NAME              [SEVERITY]   0.93 ▰▰▰▰▰▰▰▱   SOURCE   DATE   [Detected]   ›
//      file path subtext
//
// Row click selects it. Hover lifts background.  Severity dot + badge use
// the strict severity palette only. No emojis anywhere — `›` is the unicode
// chevron U+203A, not an icon.
// ============================================================================

#include <QFrame>
#include <QString>

class QLabel;
class QFrame;

class ThreatRow : public QFrame
{
    Q_OBJECT
public:
    explicit ThreatRow(QWidget* parent = nullptr);

    /// Severity is one of: "critical", "suspicious", "needs-review", "clean".
    /// Anything else falls back to "needs-review" (amber).
    void setSeverity(const QString& severity);
    void setThreatName(const QString& name);
    void setSubtext(const QString& subtext);
    void setConfidence(float zeroToOne);   // displayed as "0.93" + bar
    void setSource(const QString& source);
    void setDetected(const QString& displayText);
    void setStatus(const QString& status); // typically "Detected"

    /// Sticky-selected state (highlight + accent left edge).
    void setSelected(bool selected);
    bool isSelected() const { return m_selected; }

    /// Caller-supplied opaque payload (typically the index of the
    /// SuspiciousFile inside MainWindow::m_findings). The Results page
    /// uses this to find the right finding when a row is clicked.
    void setPayload(int payload) { m_payload = payload; }
    int  payload() const          { return m_payload; }

signals:
    void clicked(int payload);

protected:
    void mouseReleaseEvent(QMouseEvent* e) override;
    void enterEvent(QEnterEvent* e) override;
    void leaveEvent(QEvent* e) override;

private:
    void applyVisualState();

    // ── Cells ──────────────────────────────────────────────────────────
    QLabel* m_dot           = nullptr;   // colored severity dot, 8 px
    QLabel* m_name          = nullptr;   // bold threat name
    QLabel* m_subtext       = nullptr;   // truncated path / subsource
    QLabel* m_severityBadge = nullptr;
    QLabel* m_confidenceNum = nullptr;
    QFrame* m_confidenceBar = nullptr;   // filled rect inside a track
    QFrame* m_confidenceFill = nullptr;
    QLabel* m_source        = nullptr;
    QLabel* m_detected      = nullptr;
    QLabel* m_statusBadge   = nullptr;
    QLabel* m_chevron       = nullptr;

    // ── State ──────────────────────────────────────────────────────────
    QString m_severity;
    bool    m_selected = false;
    bool    m_hovered  = false;
    int     m_payload  = -1;
};
