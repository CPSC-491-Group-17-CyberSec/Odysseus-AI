#pragma once
// ============================================================================
// AlertTypes.h  –  Phase 4: shared types for the EDR-Lite continuous
// monitoring service. All types are plain value-types so they can cross
// thread boundaries via Qt::QueuedConnection after qRegisterMetaType.
//
// An Alert is the single output unit emitted by MonitoringService when the
// SnapshotDiff engine detects a meaningful change between two consecutive
// system snapshots. Every Alert is self-describing — title is short for
// list rendering, description is paragraph-form for the detail panel,
// rawDetail carries the underlying technical context (process cmdline,
// SHA-256, plist path, etc.) for analysts who want the full picture.
// ============================================================================

#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QMetaType>

namespace EDR {

// ── Severity levels (Info < Low < Medium < High < Critical) ────────────────
enum class Severity {
    Info     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
};

QString severityToText(Severity s);
const char* severityHex(Severity s);    // hex string from the strict palette

// ── Alert lifecycle status (dedup engine) ──────────────────────────────────
//   Active   — condition observed in the latest tick
//   Resolved — condition disappeared at least one tick ago
enum class AlertStatus {
    Active   = 0,
    Resolved = 1,
};

QString alertStatusToText(AlertStatus s);

// ── Categories (used by the UI to group / filter alerts) ───────────────────
namespace Category {
    inline constexpr const char* Process     = "process";
    inline constexpr const char* Persistence = "persistence";
    inline constexpr const char* CrossView   = "crossview";
    inline constexpr const char* Integrity   = "integrity";
    inline constexpr const char* KernelExt   = "kext";
    inline constexpr const char* Service     = "service";   // EDR self-events
}

// ---------------------------------------------------------------------------
// Alert  –  one finding produced by SnapshotDiff
// ---------------------------------------------------------------------------
struct Alert
{
    QString    id;                  // UUID-ish, unique per session
    QDateTime  timestamp;           // when the diff produced it
    Severity   severity = Severity::Info;
    QString    category;            // see EDR::Category
    QString    title;               // short headline for list rows
    QString    description;         // longer paragraph for detail view
    QString    sourcePath;          // path or process name (whatever fits)
    QString    recommendedAction;
    QString    rawDetail;           // technical context: cmdline, hashes,
                                    // bullet list of indicators, etc.

    // ── Polish-pass structured fields (all optional) ─────────────────
    // The UI renders only the fields that are populated. SnapshotDiff
    // fills these in per-category; categories that don't apply leave
    // them at their default values.
    QDateTime   firstSeen;          // for grouped alerts (UI-side grouping)
    QDateTime   lastSeen;
    int         occurrenceCount = 1;

    int         pid       = -1;     // process / cross-view alerts
    int         parentPid = -1;
    QString     cmdline;
    QString     user;

    QString     sha256;             // integrity / file alerts
    int         signingStatus = -1; // -1=unknown, 0=unsigned,
                                    //  1=signed-untrusted, 2=signed-trusted
    QString     signerInfo;
    QString     reputationFamily;

    QStringList yaraMatches;        // file alerts (future use)
    QStringList heuristics;         // human-readable bullets:
                                    //   "runs from /tmp",
                                    //   "unsigned binary", etc.

    // ── Dedup engine fields ──────────────────────────────────────────
    // dedupKey is a stable identifier for the underlying condition (NOT
    // the alert event). Two alerts with the same dedupKey describe the
    // same finding — MonitoringService folds them so the user sees one
    // long-running alert with first/last seen + occurrence count instead
    // of a fresh row every tick.
    //
    // status   — Active while the condition is still observed in ticks;
    //            flips to Resolved when it disappears. Resolved alerts
    //            stay in history (for audit) but are visually muted.
    // ticksSeen — number of monitoring ticks the condition was observed
    //             (used by the risk-based scoring "persistence penalty").
    // resolvedAt — set when status flips to Resolved.
    QString     dedupKey;
    AlertStatus status     = AlertStatus::Active;
    int         ticksSeen  = 1;
    QDateTime   resolvedAt;
};

}  // namespace EDR

Q_DECLARE_METATYPE(EDR::Alert)
