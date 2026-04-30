#pragma once
// ============================================================================
// SeverityBadge.h  –  small reusable colored severity pill.
//
// Strict palette mapping:
//   Critical → red    #EF4444
//   High      → orange #F59E0B
//   Medium    → yellow #F59E0B (same family)
//   Low       → blue   #3B82F6
//   Info      → gray   #9CA3AF
//
// Two visual styles:
//   Filled     — colored bg + white text (used in detail panel header)
//   Outlined   — colored border + matching text on transparent (default,
//                used in row lists, less visually heavy)
// ============================================================================

#include <QLabel>

#include "../../../include/edr/AlertTypes.h"

class SeverityBadge : public QLabel {
  Q_OBJECT
 public:
  enum Style { Outlined, Filled };

  explicit SeverityBadge(QWidget* parent = nullptr);
  explicit SeverityBadge(EDR::Severity sev, Style style = Outlined, QWidget* parent = nullptr);

  void setSeverity(EDR::Severity sev);
  void setBadgeStyle(Style style);

 private:
  void rerender();

  EDR::Severity m_severity = EDR::Severity::Info;
  Style m_style = Outlined;
};
