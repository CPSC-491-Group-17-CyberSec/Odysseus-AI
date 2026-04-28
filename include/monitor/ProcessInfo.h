#pragma once
// ============================================================================
// ProcessInfo.h  –  Phase 2: shared data structures for system monitoring
//
// All system-monitoring modules (enumerator, persistence scanner, heuristics,
// orchestrator) operate on these plain value types. No QObject inheritance;
// these are safe to copy across threads via Qt::QueuedConnection.
// ============================================================================

#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QVector>
#include <QMetaType>

// Phase 3: rootkit findings travel inside SystemSnapshot
#include "rootkit/RootkitTypes.h"

// ---------------------------------------------------------------------------
// ProcessInfo  –  one running process's read-only metadata
//
// Field availability:
//   pid, name, ppid, uid           always populated (sysctl / /proc)
//   user                            best-effort getpwuid; may be numeric uid string
//   exePath                         macOS proc_pidpath / Linux readlink /proc/<pid>/exe
//                                   May be empty if EPERM (sandboxed app, other user)
//                                   May end in " (deleted)" on Linux when binary was unlinked
//   cmdLine                         macOS KERN_PROCARGS2 / Linux /proc/<pid>/cmdline
//                                   May be "(restricted)" if EPERM
//   exeMissing                     true if exePath is set but the file no longer exists
//   isOurProcess                   true if pid == getpid() — used to suppress
//                                   self-flagging in the heuristics pass
// ---------------------------------------------------------------------------
struct ProcessInfo
{
    int         pid          = 0;
    int         ppid         = 0;
    int         uid          = -1;
    QString     name;          // short name (truncated to 16 chars on macOS)
    QString     user;          // resolved username, falls back to "uid:<n>"
    QString     exePath;
    QString     cmdLine;
    bool        exeMissing   = false;
    bool        isOurProcess = false;
};

// ---------------------------------------------------------------------------
// SuspiciousProcess  –  a ProcessInfo that one or more heuristics flagged
// ---------------------------------------------------------------------------
struct SuspiciousProcess
{
    ProcessInfo  info;
    QStringList  reasons;          // human-readable why flagged
    QString      severity;         // "low" / "medium" / "high"
    int          score    = 0;     // 0–100; sum of triggered heuristic weights
    int          signingStatus = -1;  // CodeSigning::Status as int (-1 if not checked)
    QString      signerId;
};

// ---------------------------------------------------------------------------
// PersistenceItem  –  one persistence mechanism we found on disk
//
// Type values:
//   "LaunchAgent"        – ~/Library/LaunchAgents/*.plist or /Library/LaunchAgents
//   "LaunchDaemon"       – /Library/LaunchDaemons/*.plist
//   "UserCron"           – `crontab -l` for the current user
//   "SystemCron"         – /etc/crontab, /etc/cron.d/*
//   "SystemdUnit"        – /etc/systemd/system/*.service (Linux only)
//   "SystemdUserUnit"    – ~/.config/systemd/user/*.service (Linux only)
// ---------------------------------------------------------------------------
struct PersistenceItem
{
    QString     type;
    QString     label;             // launchd Label, cron schedule, unit name, ...
    QString     filePath;          // where on disk it lives (empty for crontab -l output)
    QString     program;           // executable that gets run
    QStringList programArgs;       // full argv if available
    bool        runAtLoad   = false;  // launchd RunAtLoad
    bool        keepAlive   = false;  // launchd KeepAlive
    QString     scheduleHint;      // human-readable schedule (cron line, "at boot", etc.)
    QStringList notes;             // anything we noticed (unsigned target, /tmp path, ...)
    QString     severity;          // "low" / "medium" / "high"
    QDateTime   lastModified;
};

// ---------------------------------------------------------------------------
// SystemSnapshot  –  one full system-monitor pass
// ---------------------------------------------------------------------------
struct SystemSnapshot
{
    QDateTime                   capturedAt;
    int                         totalProcesses = 0;
    QVector<ProcessInfo>        processes;
    QVector<SuspiciousProcess>  suspicious;
    QVector<PersistenceItem>    persistence;

    // Diagnostics so the UI can show "we couldn't read N command lines"
    int                         restrictedCmdlines = 0;
    QString                     platformLabel;       // "macOS", "Linux", "unknown"

    // Phase 3 — rootkit-awareness findings (defaults to ran=false if disabled)
    RootkitSnapshot             rootkit;
};

// Required for queued signals across thread boundaries.
Q_DECLARE_METATYPE(ProcessInfo)
Q_DECLARE_METATYPE(SuspiciousProcess)
Q_DECLARE_METATYPE(PersistenceItem)
Q_DECLARE_METATYPE(SystemSnapshot)
