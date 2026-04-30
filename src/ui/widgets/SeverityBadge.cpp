// ============================================================================
// SeverityBadge.cpp
// ============================================================================

#include "SeverityBadge.h"
#include "../theme/DashboardTheme.h"

namespace {

const char* hexFor(EDR::Severity s)
{
    // Strict palette per the polish brief:
    //   Critical = red, High = orange, Medium = yellow,
    //   Low/Info = blue/gray.
    switch (s) {
        case EDR::Severity::Critical: return "#EF4444";
        case EDR::Severity::High:     return "#F97316";
        case EDR::Severity::Medium:   return "#F59E0B";
        case EDR::Severity::Low:      return Theme::Color::accentBlue;
        case EDR::Severity::Info:     return Theme::Color::textSecondary;
    }
    return Theme::Color::textSecondary;
}

}  // anonymous

SeverityBadge::SeverityBadge(QWidget* parent)
    : QLabel(parent)
{
    setAlignment(Qt::AlignCenter);
    rerender();
}

SeverityBadge::SeverityBadge(EDR::Severity sev, Style style, QWidget* parent)
    : QLabel(parent), m_severity(sev), m_style(style)
{
    setAlignment(Qt::AlignCenter);
    rerender();
}

void SeverityBadge::setSeverity(EDR::Severity sev)
{
    m_severity = sev;
    rerender();
}

void SeverityBadge::setBadgeStyle(Style style)
{
    m_style = style;
    rerender();
}

void SeverityBadge::rerender()
{
    setText(EDR::severityToText(m_severity));
    const QString hex = hexFor(m_severity);

    setMinimumWidth(76);
    if (m_style == Filled) {
        setStyleSheet(QString(
            "QLabel { color: white; background-color: %1;"
            " border-radius: 6px; padding: 3px 10px; %2 }")
                .arg(hex)
                .arg(Theme::Type::qss(Theme::Type::Caption,
                                        Theme::Type::WeightBold)));
    } else {
        setStyleSheet(QString(
            "QLabel { color: %1; background: transparent;"
            " border: 1px solid %1; border-radius: 6px;"
            " padding: 3px 10px; %2 }")
                .arg(hex)
                .arg(Theme::Type::qss(Theme::Type::Caption,
                                        Theme::Type::WeightSemi)));
    }
}
