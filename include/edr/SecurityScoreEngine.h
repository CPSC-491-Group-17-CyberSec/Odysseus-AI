#pragma once
// ============================================================================
// SecurityScoreEngine.h  –  risk-based system security score.
//
// Replaces the old "subtract a fixed amount per finding type" formula with
// a model that weighs by SEVERITY, caps the impact of low-signal findings,
// and rewards transient noise resolving on its own.
//
// Algorithm (per the user spec):
//
//   Start at 100.
//   For each ACTIVE alert in the live dedup map:
//
//     • Critical          : -30 each (no cap)
//     • High              : -15 each (no cap)
//     • Medium            :  -5 each, total Medium loss capped at -25
//     • Low / Info        :  -1 each, total Low loss capped at -10
//
//     Cross-view alerts are forced to Low weight AND only counted if the
//     alert's ticksSeen ≥ kCrossViewMinTicks (i.e. persistent across
//     multiple monitoring ticks). One-tick cross-view churn is ignored.
//
//     Persistence penalty: any alert with ticksSeen ≥ kPersistenceMinTicks
//     contributes an extra -10 (once per alert, not per severity).
//
//   Final score is clamped to [0, 100].
//
// Output:
//   • int score
//   • Label: 80–100 = Secure, 50–79 = Moderate, <50 = High Risk
//   • Breakdown: ordered list of "−N · reason" lines suitable for UI
//
// Pure function. No Qt event loop interaction. Used by DashboardPage to
// render the score, and by ResultsPage / Settings if they want the same
// number on display.
// ============================================================================

#include "AlertTypes.h"

#include <QString>
#include <QStringList>
#include <QHash>

namespace EDR {

enum class ScoreLabel {
    Secure   = 0,    // 80–100
    Moderate = 1,    // 50–79
    HighRisk = 2,    // < 50
};

QString scoreLabelToText(ScoreLabel l);
const char* scoreLabelHex(ScoreLabel l);

struct ScoreLine {
    int     delta;     // negative — points lost
    QString reason;    // human-readable, e.g. "1 critical alert"
};

struct ScoreReport {
    int                 score = 100;
    ScoreLabel          label = ScoreLabel::Secure;
    QVector<ScoreLine>  breakdown;     // ordered, biggest impact first
    int                 activeAlerts   = 0;
    int                 criticalCount  = 0;
    int                 highCount      = 0;
    int                 mediumCount    = 0;
    int                 lowCount       = 0;
    int                 persistentCount = 0;
};

namespace ScoreConstants {
    // Per-severity penalties
    constexpr int kCriticalPenalty = 30;   // each
    constexpr int kHighPenalty     = 15;   // each
    constexpr int kMediumPenalty   = 5;    // each
    constexpr int kLowPenalty      = 1;    // each

    // Caps on total per-severity loss
    constexpr int kMediumCap       = 25;
    constexpr int kLowCap          = 10;

    // Persistence threshold + extra penalty
    constexpr int kPersistenceMinTicks = 2;   // ≥ N ticks = "persistent"
    constexpr int kPersistencePenalty  = 10;  // extra per persistent alert

    // Cross-view minimum ticks to count at all
    constexpr int kCrossViewMinTicks   = 2;
}

/// Score the supplied set of currently-ACTIVE alerts (typically from
/// MonitoringService::activeAlerts()). Resolved alerts should NOT be
/// passed in — they don't reflect current risk.
ScoreReport scoreActiveAlerts(const QHash<QString, Alert>& activeAlerts);

}  // namespace EDR
