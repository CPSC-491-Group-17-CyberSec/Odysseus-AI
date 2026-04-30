#pragma once
// ============================================================================
// AlertRow.h  –  one row in the Alerts list.
//
// Layout (matches the polish brief):
//   ●  HH:MM  CATEGORY-icon  CATEGORY  Title (truncated)         Source-path
//      [outlined severity badge]                       [chevron / expand]
//
// State:
//   • Hover    → bg lifts to bgCardHover
//   • Selected → bg lifts AND severity-colored 3px left accent
//   • Zebra    → alternates with a subtle bgSecondary tint
//   • Group    → if occurrenceCount > 1, the title shows "(N occurrences)"
//                and the chevron rotates to indicate expandable group
// ============================================================================

#include "../../../include/edr/AlertTypes.h"

#include <QFrame>

class QLabel;
class SeverityBadge;

class AlertRow : public QFrame
{
    Q_OBJECT
public:
    explicit AlertRow(QWidget* parent = nullptr);

    /// Apply alert content + visual state. `index` is the caller-supplied
    /// payload returned in the clicked() signal so callers can map back
    /// into their own data structures.
    void setAlert(const EDR::Alert& alert,
                   int               index,
                   int               occurrenceCount = 1,
                   bool              isGroupHeader   = false);

    void setSelected(bool sel);
    void setZebra(bool z);

signals:
    void clicked(int index);

protected:
    void mouseReleaseEvent(QMouseEvent* e) override;
    void enterEvent(QEnterEvent* e) override;
    void leaveEvent(QEvent* e) override;

private:
    void applyStyle();
    static QString smartTruncate(const QString& path, int maxLen = 60);
    static const char* iconForCategory(const QString& category);

    SeverityBadge* m_badge      = nullptr;
    QLabel*        m_dot        = nullptr;       // category color dot
    QLabel*        m_categoryIcon = nullptr;     // small text icon
    QLabel*        m_categoryLab  = nullptr;
    QLabel*        m_titleLab   = nullptr;
    QLabel*        m_sourceLab  = nullptr;
    QLabel*        m_timeLab    = nullptr;
    QLabel*        m_chevron    = nullptr;

    EDR::Severity  m_severity   = EDR::Severity::Info;
    int            m_index      = -1;
    bool           m_selected   = false;
    bool           m_hovered    = false;
    bool           m_zebra      = false;
    bool           m_isGroup    = false;
    bool           m_resolved   = false;
};
