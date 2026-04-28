#pragma once
// ============================================================================
// RootkitTypes.h  –  Phase 3 shared data structures
//
// All rootkit-awareness modules return findings via these plain value types.
// They piggyback on the existing SystemSnapshot delivered by SystemMonitor,
// so the UI gets one snapshotReady() per refresh containing process,
// persistence, AND rootkit findings.
//
// No QObject inheritance — these cross thread boundaries via Qt::QueuedConnection
// after qRegisterMetaType (registered in SystemMonitor.cpp).
// ============================================================================

#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QVector>
#include <QMetaType>

// ---------------------------------------------------------------------------
// CrossViewFinding  –  one PID that disagrees between sysctl and ps
// ---------------------------------------------------------------------------
struct CrossViewFinding
{
    int     pid       = 0;
    QString name;          // process name from whichever side knew about it
    QString visibleIn;     // "sysctl-only" / "ps-only"
    QString reason;        // human-readable description
    QString severity;      // "low" / "medium" / "high"
};

// ---------------------------------------------------------------------------
// KernelExtension  –  one loaded kext / system extension
//
// Source can be either:
//   • "system_extension"   – modern macOS DriverKit/EndpointSecurity/NetworkExt
//   • "legacy_kext"        – kmutil showloaded entry
//   • "linux_module"       – /proc/modules / lsmod
// ---------------------------------------------------------------------------
struct KernelExtension
{
    QString source;          // see above
    QString bundleId;        // com.apple.kpi.bsd, com.example.driver
    QString teamId;          // 10-char Apple Developer Team ID, or empty
    QString version;
    QString name;            // human-readable name
    QString state;           // "activated", "loaded", "terminated", ...
    QString signedBy;        // Apple / Developer ID Application: ... / "(unsigned)"
    bool    isApple   = false;
    bool    isUserspace = false;   // system extensions run in user space
    QStringList notes;
    QString severity;        // "low" / "medium" / "high"
};

// ---------------------------------------------------------------------------
// IntegrityFinding  –  one critical-path hash mismatch (or new baseline entry)
// ---------------------------------------------------------------------------
struct IntegrityFinding
{
    QString path;
    QString status;          // "ok", "mismatch", "missing", "new", "rebased"
    QString expectedHash;    // baseline value (hex); empty if status==new
    QString currentHash;     // computed this run; empty if status==missing
    qint64  currentSize  = 0;
    QString severity;        // "low" (new/ok) / "medium" (missing) / "high" (mismatch)
    QString note;
};

// ---------------------------------------------------------------------------
// RootkitSnapshot  –  everything the rootkit pass produced this round
// ---------------------------------------------------------------------------
struct RootkitSnapshot
{
    bool                       ran             = false;
    QString                    macosVersion;       // "15.4" etc
    bool                       baselineCreated = false;  // first-run flag
    bool                       baselineRebased = false;  // OS version changed since baseline

    QVector<CrossViewFinding>  crossView;
    QVector<KernelExtension>   extensions;
    QVector<IntegrityFinding>  integrity;

    int processSysctlCount  = 0;
    int processPsCount      = 0;
    int extensionsTotal     = 0;
    int integrityChecked    = 0;
    int integrityMismatches = 0;
};

Q_DECLARE_METATYPE(CrossViewFinding)
Q_DECLARE_METATYPE(KernelExtension)
Q_DECLARE_METATYPE(IntegrityFinding)
Q_DECLARE_METATYPE(RootkitSnapshot)
