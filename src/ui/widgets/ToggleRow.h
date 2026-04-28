#pragma once
// ============================================================================
// ToggleRow.h  –  Step 4 building blocks for the Settings page.
//
//   ToggleSwitch  – custom-painted pill with a sliding knob (no QCheckBox).
//                   Same look across macOS / Linux, no system-style drift.
//   ToggleRow     – label + description on the left, a ToggleSwitch on the
//                   right. Used by SettingsPage for every config toggle.
//
// Both are plain QWidget subclasses with Q_OBJECT so signals work across
// thread boundaries (not relevant here, but keeps the pattern consistent
// with the rest of the codebase).
// ============================================================================

#include <QWidget>
#include <QFrame>
#include <QString>

class QLabel;

// ---------------------------------------------------------------------------
// ToggleSwitch  –  painted pill (40×22) with a sliding knob.
// ---------------------------------------------------------------------------
class ToggleSwitch : public QWidget
{
    Q_OBJECT
public:
    explicit ToggleSwitch(QWidget* parent = nullptr);

    bool isChecked() const { return m_checked; }
    /// Programmatic state change. Emits `toggled` if the value changed.
    void setChecked(bool checked);

signals:
    void toggled(bool checked);

protected:
    void paintEvent(QPaintEvent*) override;
    void mouseReleaseEvent(QMouseEvent*) override;
    QSize sizeHint() const override;

private:
    bool m_checked = false;
};

// ---------------------------------------------------------------------------
// ToggleRow  –  one labeled toggle row used by SettingsPage.
// ---------------------------------------------------------------------------
class ToggleRow : public QFrame
{
    Q_OBJECT
public:
    ToggleRow(const QString& label,
               const QString& description,
               QWidget*       parent = nullptr);

    bool isChecked() const;
    void setChecked(bool checked);

signals:
    void toggled(bool checked);

private:
    QLabel*       m_label       = nullptr;
    QLabel*       m_description = nullptr;
    ToggleSwitch* m_switch      = nullptr;
};
