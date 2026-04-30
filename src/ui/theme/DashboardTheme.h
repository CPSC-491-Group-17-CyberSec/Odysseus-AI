#pragma once
// ============================================================================
// DashboardTheme.h  –  centralized palette + global stylesheet for the
// Phase 4 redesign. Every new widget pulls its colors from here so the
// theme can be retuned in one place.
//
// Color tokens follow the mockup:
//   • bgPrimary       – outermost app background (deep navy)
//   • bgSecondary     – card / panel background
//   • bgSidebar       – sidebar column
//   • borderSubtle    – 1px dividers between cards
//   • textPrimary     – default text (off-white)
//   • textSecondary   – labels, captions
//   • accentBlue      – selected nav, primary CTA, links
//   • severity[Crit|High|Med|Low]  – red/orange/yellow/green
//
// Apply once at app startup via Theme::install(QApplication*).
// ============================================================================

#include <QString>

class QApplication;

namespace Theme {

// ── Color palette (hex strings, used directly in stylesheets) ──────────────
//   Strict enterprise-cybersecurity palette. Every UI surface must pick
//   from this set; ad-hoc colors are not allowed elsewhere in the codebase.
namespace Color {
// Surfaces
inline constexpr const char* bgPrimary = "#0B1220";     // app background
inline constexpr const char* bgSecondary = "#111827";   // alt cards / row stripes
inline constexpr const char* bgSidebar = "#0F1729";     // sidebar column (a touch darker)
inline constexpr const char* bgCard = "#111827";        // standard card
inline constexpr const char* bgCardHover = "#1A2436";   // hover row tint
inline constexpr const char* borderSubtle = "#1F2937";  // 1px dividers
inline constexpr const char* borderAccent = "#3B82F6";

// Text
inline constexpr const char* textPrimary = "#E5E7EB";    // body text
inline constexpr const char* textSecondary = "#9CA3AF";  // labels, captions
inline constexpr const char* textMuted = "#6B7280";      // muted metadata

// Accent
inline constexpr const char* accentBlue = "#3B82F6";
inline constexpr const char* accentBlueHover = "#2563EB";
inline constexpr const char* accentBlueSoft = "#1E3A8A";  // selection bg

// Severities (single source of truth)
inline constexpr const char* severityCritical = "#EF4444";  // red
inline constexpr const char* severityHigh = "#F59E0B";      // amber  (alias of medium)
inline constexpr const char* severityMedium = "#F59E0B";    // amber
inline constexpr const char* severityLow = "#F59E0B";       // amber  (alias)
inline constexpr const char* severitySafe = "#10B981";      // green  (clean)
inline constexpr const char* severityInfo = "#3B82F6";      // accent blue
}  // namespace Color

// ── Sizes ──────────────────────────────────────────────────────────────────
namespace Size {
inline constexpr int sidebarWidth = 240;
inline constexpr int detailsPanelWidth = 420;
inline constexpr int cardRadius = 12;
inline constexpr int sidebarBtnRadius = 10;
inline constexpr int tableRowHeight = 48;
}  // namespace Size

// ── Typography (px sizes; weights as enums) ────────────────────────────────
// One scale used across every page so headings, card titles, body, and
// captions never drift. The companion `qss(...)` helpers emit the matching
// `font-size: %dpx; font-weight: %d;` block for inline use.
namespace Type {
inline constexpr int Display = 28;  // page hero ("Welcome back")
inline constexpr int H1 = 22;       // section headers
inline constexpr int H2 = 16;       // card titles
inline constexpr int H3 = 14;       // sub-card titles
inline constexpr int Body = 13;     // default body text
inline constexpr int Small = 12;    // labels, dense table rows
inline constexpr int Caption = 11;  // KPI captions, footers
inline constexpr int Tiny = 10;     // hash strings, taglines

inline constexpr int WeightRegular = 400;
inline constexpr int WeightMedium = 500;
inline constexpr int WeightSemi = 600;
inline constexpr int WeightBold = 700;

/// Build a "font-size: ...; font-weight: ...;" QSS fragment.
inline QString qss(int sizePx, int weight = WeightRegular) {
  return QString("font-size: %1px; font-weight: %2;").arg(sizePx).arg(weight);
}
}  // namespace Type

/// Apply dark palette + global stylesheet to the application.
/// Idempotent — safe to call more than once.
void install(QApplication* app);

/// Build the global stylesheet (exposed in case a widget needs to re-apply
/// it locally, e.g. after a child reparenting).
QString globalStyleSheet();

/// Helper: pick a severity color from a severity string ("low"/"medium"/...).
const char* severityHex(const QString& severity);

}  // namespace Theme
