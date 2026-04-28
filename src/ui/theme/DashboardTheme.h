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
namespace Color {
    inline constexpr const char* bgPrimary     = "#0F1424";
    inline constexpr const char* bgSecondary   = "#1A2138";
    inline constexpr const char* bgSidebar     = "#161B2C";
    inline constexpr const char* bgCard        = "#1E2640";
    inline constexpr const char* bgCardHover   = "#252E50";
    inline constexpr const char* borderSubtle  = "#2A3354";
    inline constexpr const char* borderAccent  = "#3B82F6";

    inline constexpr const char* textPrimary   = "#F8FAFC";
    inline constexpr const char* textSecondary = "#94A3B8";
    inline constexpr const char* textMuted     = "#64748B";

    inline constexpr const char* accentBlue       = "#3B82F6";
    inline constexpr const char* accentBlueHover  = "#2563EB";
    inline constexpr const char* accentBlueSoft   = "#1E40AF";   // 20% bg use

    inline constexpr const char* severityCritical = "#EF4444";
    inline constexpr const char* severityHigh     = "#F97316";
    inline constexpr const char* severityMedium   = "#F59E0B";
    inline constexpr const char* severityLow      = "#FACC15";
    inline constexpr const char* severitySafe     = "#22C55E";
    inline constexpr const char* severityInfo     = "#3B82F6";
}  // namespace Color

// ── Sizes ──────────────────────────────────────────────────────────────────
namespace Size {
    inline constexpr int sidebarWidth     = 240;
    inline constexpr int detailsPanelWidth = 420;
    inline constexpr int cardRadius       = 12;
    inline constexpr int sidebarBtnRadius = 10;
    inline constexpr int tableRowHeight   = 48;
}

// ── Typography (px sizes; weights as enums) ────────────────────────────────
// One scale used across every page so headings, card titles, body, and
// captions never drift. The companion `qss(...)` helpers emit the matching
// `font-size: %dpx; font-weight: %d;` block for inline use.
namespace Type {
    inline constexpr int Display = 28;   // page hero ("Welcome back")
    inline constexpr int H1      = 22;   // section headers
    inline constexpr int H2      = 16;   // card titles
    inline constexpr int H3      = 14;   // sub-card titles
    inline constexpr int Body    = 13;   // default body text
    inline constexpr int Small   = 12;   // labels, dense table rows
    inline constexpr int Caption = 11;   // KPI captions, footers
    inline constexpr int Tiny    = 10;   // hash strings, taglines

    inline constexpr int WeightRegular = 400;
    inline constexpr int WeightMedium  = 500;
    inline constexpr int WeightSemi    = 600;
    inline constexpr int WeightBold    = 700;

    /// Build a "font-size: ...; font-weight: ...;" QSS fragment.
    inline QString qss(int sizePx, int weight = WeightRegular)
    {
        return QString("font-size: %1px; font-weight: %2;")
                  .arg(sizePx).arg(weight);
    }
}

/// Apply dark palette + global stylesheet to the application.
/// Idempotent — safe to call more than once.
void install(QApplication* app);

/// Build the global stylesheet (exposed in case a widget needs to re-apply
/// it locally, e.g. after a child reparenting).
QString globalStyleSheet();

/// Helper: pick a severity color from a severity string ("low"/"medium"/...).
const char* severityHex(const QString& severity);

}  // namespace Theme
