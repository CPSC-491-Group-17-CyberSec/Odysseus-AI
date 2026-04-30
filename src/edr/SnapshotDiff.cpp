// ============================================================================
// SnapshotDiff.cpp  –  Phase 4 diff engine
// ============================================================================

#include "edr/SnapshotDiff.h"

#include <QDateTime>
#include <QHash>
#include <QSet>
#include <QUuid>

namespace EDR {

QString severityToText(Severity s) {
  switch (s) {
    case Severity::Critical:
      return "Critical";
    case Severity::High:
      return "High";
    case Severity::Medium:
      return "Medium";
    case Severity::Low:
      return "Low";
    case Severity::Info:
      return "Info";
  }
  return "Unknown";
}

QString alertStatusToText(AlertStatus s) {
  switch (s) {
    case AlertStatus::Active:
      return "Active";
    case AlertStatus::Resolved:
      return "Resolved";
  }
  return "Unknown";
}

const char* severityHex(Severity s) {
  // Strict palette already defined in DashboardTheme. We avoid pulling
  // in DashboardTheme here so this TU has zero UI dependencies.
  switch (s) {
    case Severity::Critical:
      return "#EF4444";  // red
    case Severity::High:
      return "#F59E0B";  // amber
    case Severity::Medium:
      return "#F59E0B";  // amber
    case Severity::Low:
      return "#10B981";  // green
    case Severity::Info:
      return "#3B82F6";  // accent blue
  }
  return "#3B82F6";
}

}  // namespace EDR

namespace SnapshotDiff {
namespace {

// ────────────────────────────────────────────────────────────────────────────
//  helpers
// ────────────────────────────────────────────────────────────────────────────

EDR::Severity processSeverity(const QString& raw) {
  const QString s = raw.toLower();
  if (s == "high")
    return EDR::Severity::High;
  if (s == "medium")
    return EDR::Severity::Medium;
  if (s == "low")
EDR::Severity processSeverity(const QString& raw)
{
    const QString s = raw.toLower();
    if (s == "high")     return EDR::Severity::High;
    if (s == "medium")   return EDR::Severity::Medium;
    if (s == "low")      return EDR::Severity::Low;
    if (s == "info")     return EDR::Severity::Info;   // Phase 5 — dev-tool path-only
    return EDR::Severity::Medium;     // default for suspicious processes
}

EDR::Severity persistenceSeverity(const QString& raw)
{
    const QString s = raw.toLower();
    if (s == "high")    return EDR::Severity::High;
    if (s == "medium")  return EDR::Severity::Medium;
    return EDR::Severity::Low;
  return EDR::Severity::Medium;  // default for suspicious processes
}

EDR::Severity persistenceSeverity(const QString& raw) {
  const QString s = raw.toLower();
  if (s == "high")
    return EDR::Severity::High;
  if (s == "medium")
    return EDR::Severity::Medium;
  return EDR::Severity::Low;
}

EDR::Severity kextSeverity(const QString& raw) {
  const QString s = raw.toLower();
  if (s == "high")
    return EDR::Severity::High;
  if (s == "medium")
    return EDR::Severity::Medium;
  return EDR::Severity::Info;
}

// ID factory — short UUID without braces, plenty for in-memory dedup.
QString newId() {
  return QUuid::createUuid().toString(QUuid::WithoutBraces).left(12);
}

// ────────────────────────────────────────────────────────────────────────────
//  per-category diff helpers
// ────────────────────────────────────────────────────────────────────────────

// Stable keys per category — independent of PID churn so a process that
// briefly drops off the snapshot doesn't reappear as a "new" alert.
//   process      → process|<exePath || name>
//   persistence  → persistence|<type>|<label>|<filePath>
//   crossview    → crossview|<name || pid>
//   integrity    → integrity|<path>
//   kext         → kext|<bundleId>
QString keyForProcess(const SuspiciousProcess& sp) {
  const QString anchor = sp.info.exePath.isEmpty() ? sp.info.name : sp.info.exePath;
  return QString("process|%1").arg(anchor);
}

void diffSuspiciousProcesses(
    const SystemSnapshot& prev,
    const SystemSnapshot& curr,
    QVector<EDR::Alert>& out,
    QHash<QString, EDR::Alert>& currentKeys) {
  QSet<QString> prevKeys;
  for (const SuspiciousProcess& sp : prev.suspicious)
    prevKeys.insert(keyForProcess(sp));

  for (const SuspiciousProcess& sp : curr.suspicious) {
    const QString key = keyForProcess(sp);

    EDR::Alert a;
    a.id = newId();
    a.dedupKey = key;
    a.timestamp = QDateTime::currentDateTime();
    a.firstSeen = a.timestamp;
    a.lastSeen = a.timestamp;
    a.severity = processSeverity(sp.severity);
    a.category = EDR::Category::Process;
    a.title = QString("Suspicious process: %1").arg(sp.info.name);
    a.description = sp.reasons.isEmpty() ? QStringLiteral("A suspicious process is running.")
                                         : sp.reasons.first();
    a.sourcePath = sp.info.exePath.isEmpty() ? sp.info.name : sp.info.exePath;
    a.recommendedAction =
        "Review the process and its origin. Terminate if unfamiliar; "
        "investigate parent process and command line.";
        EDR::Alert a;
        a.id        = newId();
        a.dedupKey  = key;
        a.timestamp = QDateTime::currentDateTime();
        a.firstSeen = a.timestamp;
        a.lastSeen  = a.timestamp;
        a.severity  = processSeverity(sp.severity);
        a.category  = EDR::Category::Process;
        // Title is severity-aware: Info/Low (e.g. dev-tool path-only) reads
        // as "Process needs review" instead of the alarming "Suspicious
        // process". This is the user-visible part of the cpptools-srv /
        // VS Code false-positive fix.
        a.title = (a.severity == EDR::Severity::Info
                   || a.severity == EDR::Severity::Low)
                      ? QString("Process needs review: %1").arg(sp.info.name)
                      : QString("Suspicious process: %1").arg(sp.info.name);
        a.description = sp.reasons.isEmpty()
            ? QStringLiteral("A process needs review.")
            : sp.reasons.first();
        a.sourcePath  = sp.info.exePath.isEmpty()
                          ? sp.info.name : sp.info.exePath;
        a.recommendedAction =
            "Review the process and its origin. Terminate if unfamiliar; "
            "investigate parent process and command line.";

    // Structured fields (Polish.A)
    a.pid = sp.info.pid;
    a.parentPid = sp.info.ppid;
    a.cmdline = sp.info.cmdLine;
    a.user = sp.info.user;
    a.signingStatus = sp.signingStatus;
    a.signerInfo = sp.signerId;
    a.heuristics = sp.reasons;

    QString detail;
    detail += QString("PID: %1\nPPID: %2\nUser: %3\nExe: %4\n")
                  .arg(sp.info.pid)
                  .arg(sp.info.ppid)
                  .arg(sp.info.user, sp.info.exePath);
    if (!sp.info.cmdLine.isEmpty())
      detail += QString("Cmd: %1\n").arg(sp.info.cmdLine);
    if (!sp.reasons.isEmpty()) {
      detail += "\nIndicators:\n";
      for (const QString& r : sp.reasons)
        detail += " - " + r + "\n";
    }
    a.rawDetail = detail.trimmed();

    currentKeys.insert(key, a);
    if (!prevKeys.contains(key))
      out.append(std::move(a));
  }
}

QString keyForPersistence(const PersistenceItem& p) {
  return QString("persistence|%1|%2|%3").arg(p.type, p.label, p.filePath);
}

void diffPersistence(
    const SystemSnapshot& prev,
    const SystemSnapshot& curr,
    QVector<EDR::Alert>& out,
    QHash<QString, EDR::Alert>& currentKeys) {
  QSet<QString> prevKeys;
  for (const PersistenceItem& p : prev.persistence)
    prevKeys.insert(keyForPersistence(p));

  for (const PersistenceItem& p : curr.persistence) {
    const QString key = keyForPersistence(p);

    EDR::Alert a;
    a.id = newId();
    a.dedupKey = key;
    a.timestamp = QDateTime::currentDateTime();
    a.firstSeen = a.timestamp;
    a.lastSeen = a.timestamp;
    a.severity = persistenceSeverity(p.severity);
    a.category = EDR::Category::Persistence;
    a.title = QString("Persistence item: %1").arg(p.label);
    a.description = QString(
                        "A %1 entry exists. Persistence items run "
                        "automatically on login or boot — verify "
                        "it's expected.")
                        .arg(p.type);
    a.sourcePath = p.filePath.isEmpty() ? p.program : p.filePath;
    a.recommendedAction =
        "Inspect the entry. If you didn't install this software or the "
        "schedule, remove the entry and quarantine the target binary.";
    a.heuristics = p.notes;
    QString detail;
    detail += QString("Type: %1\nLabel: %2\n").arg(p.type, p.label);
    if (!p.filePath.isEmpty())
      detail += "File: " + p.filePath + "\n";
    if (!p.program.isEmpty())
      detail += "Program: " + p.program + "\n";
    if (!p.programArgs.isEmpty())
      detail += "Args: " + p.programArgs.join(' ') + "\n";
    if (!p.scheduleHint.isEmpty())
      detail += "Schedule: " + p.scheduleHint + "\n";
    if (!p.notes.isEmpty()) {
      detail += "\nNotes:\n";
      for (const QString& n : p.notes)
        detail += " - " + n + "\n";
    }
    a.rawDetail = detail.trimmed();

    currentKeys.insert(key, a);
    if (!prevKeys.contains(key))
      out.append(std::move(a));
  }
}

QString keyForCrossView(const CrossViewFinding& f) {
  // Process names are stable across ticks; PIDs aren't (a hidden process
  // can briefly resurface with a fresh PID). Anchor on name+visibleIn.
  const QString anchor = f.name.isEmpty() ? QString::number(f.pid) : f.name;
  return QString("crossview|%1|%2").arg(anchor, f.visibleIn);
}

void diffCrossView(
    const SystemSnapshot& prev,
    const SystemSnapshot& curr,
    QVector<EDR::Alert>& out,
    QHash<QString, EDR::Alert>& currentKeys) {
  QSet<QString> prevKeys;
  for (const CrossViewFinding& f : prev.rootkit.crossView)
    prevKeys.insert(keyForCrossView(f));

  for (const CrossViewFinding& f : curr.rootkit.crossView) {
    const QString key = keyForCrossView(f);

    EDR::Alert a;
    a.id = newId();
    a.dedupKey = key;
    a.timestamp = QDateTime::currentDateTime();
    a.firstSeen = a.timestamp;
    a.lastSeen = a.timestamp;
    // Cross-view churns due to ProcessEnumerator races. Per the
    // risk-based scoring spec, treat as Low until persistence raises
    // it. The score engine separately enforces "only count if
    // persistent across multiple ticks".
    a.severity = EDR::Severity::Low;
    a.category = EDR::Category::CrossView;
    a.title = QString("Process cross-view mismatch: %1")
                  .arg(f.name.isEmpty() ? QString("PID %1").arg(f.pid) : f.name);
    a.description = f.reason;
    a.sourcePath = f.name;
    a.recommendedAction =
        "Re-run System Status. If the mismatch persists across multiple "
        "ticks, investigate as a possible userland process-hiding hook.";
    a.pid = f.pid;
    a.heuristics << f.reason;
    a.rawDetail = QString("PID: %1\nName: %2\nVisible in: %3\nReason: %4")
                      .arg(f.pid)
                      .arg(f.name, f.visibleIn, f.reason);

    currentKeys.insert(key, a);
    if (!prevKeys.contains(key))
      out.append(std::move(a));
  }
}

QString keyForIntegrity(const IntegrityFinding& f) {
  return QString("integrity|%1").arg(f.path);
}

void diffIntegrity(
    const SystemSnapshot& prev,
    const SystemSnapshot& curr,
    QVector<EDR::Alert>& out,
    QHash<QString, EDR::Alert>& currentKeys) {
  QSet<QString> prevMismatches;
  for (const IntegrityFinding& f : prev.rootkit.integrity)
    if (f.status.toLower() == "mismatch")
      prevMismatches.insert(f.path);

  for (const IntegrityFinding& f : curr.rootkit.integrity) {
    if (f.status.toLower() != "mismatch")
      continue;

    const QString key = keyForIntegrity(f);

    EDR::Alert a;
    a.id = newId();
    a.dedupKey = key;
    a.timestamp = QDateTime::currentDateTime();
    a.firstSeen = a.timestamp;
    a.lastSeen = a.timestamp;
    a.severity = EDR::Severity::Critical;
    a.category = EDR::Category::Integrity;
    a.title = QString("Integrity mismatch: %1").arg(f.path);
    a.description =
        "A critical system binary's SHA-256 differs from the "
        "captured baseline under the SAME OS version. This "
        "indicates either tampering, filesystem corruption, "
        "or an unexpected out-of-band update.";
    a.sourcePath = f.path;
    a.recommendedAction =
        "Verify recent OS updates. If none, isolate the host and "
        "investigate as potential rootkit / supply-chain tampering.";
    a.sha256 = f.currentHash;
    a.heuristics << "SHA-256 differs from baseline"
                 << "Same OS version — out-of-band change";
    QString detail;
    detail += "Path: " + f.path + "\n";
    if (!f.expectedHash.isEmpty())
      detail += "Baseline SHA-256: " + f.expectedHash + "\n";
    if (!f.currentHash.isEmpty())
      detail += "Current SHA-256:  " + f.currentHash + "\n";
    if (f.currentSize > 0)
      detail += QString("Size: %1 bytes\n").arg(f.currentSize);
    if (!f.note.isEmpty())
      detail += "\n" + f.note;
    a.rawDetail = detail.trimmed();

    currentKeys.insert(key, a);
    if (!prevMismatches.contains(f.path))
      out.append(std::move(a));
  }
}

QString keyForKext(const KernelExtension& k) {
  return QString("kext|%1").arg(k.bundleId);
}

void diffKernelExtensions(
    const SystemSnapshot& prev,
    const SystemSnapshot& curr,
    QVector<EDR::Alert>& out,
    QHash<QString, EDR::Alert>& currentKeys) {
  QSet<QString> prevKeys;
  for (const KernelExtension& k : prev.rootkit.extensions)
    prevKeys.insert(keyForKext(k));

  for (const KernelExtension& k : curr.rootkit.extensions) {
    // Skip Apple-signed defaults — they appear/disappear with normal
    // power-management transitions and would generate noise.
    if (k.isApple && k.severity.toLower() == "low")
      continue;

    const QString key = keyForKext(k);

    EDR::Alert a;
    a.id = newId();
    a.dedupKey = key;
    a.timestamp = QDateTime::currentDateTime();
    a.firstSeen = a.timestamp;
    a.lastSeen = a.timestamp;
    a.severity = kextSeverity(k.severity);
    a.category = EDR::Category::KernelExt;
    a.title = QString("%1: %2")
                  .arg(k.source == "system_extension" ? "System extension" : "Kernel module")
                  .arg(k.bundleId);
    a.description =
        "A kernel-resident or system-extension module is "
        "loaded. Verify it was installed deliberately.";
    a.sourcePath = k.bundleId;
    a.recommendedAction =
        "Review the module's signer and bundle ID. If unfamiliar, run "
        "the System Status refresh and investigate the publishing team.";
    a.signerInfo = k.signedBy;
    a.signingStatus = k.isApple ? 2 : (k.signedBy.isEmpty() ? 0 : 1);
    a.heuristics = k.notes;
    QString detail;
    detail += "Bundle ID: " + k.bundleId + "\n";
    if (!k.version.isEmpty())
      detail += "Version: " + k.version + "\n";
    if (!k.teamId.isEmpty())
      detail += "Team ID: " + k.teamId + "\n";
    if (!k.signedBy.isEmpty())
      detail += "Signed by: " + k.signedBy + "\n";
    if (!k.state.isEmpty())
      detail += "State: " + k.state + "\n";
    if (!k.notes.isEmpty()) {
      detail += "\nNotes:\n";
      for (const QString& n : k.notes)
        detail += " - " + n + "\n";
    }
    a.rawDetail = detail.trimmed();

    currentKeys.insert(key, a);
    if (!prevKeys.contains(key))
      out.append(std::move(a));
  }
}

}  // namespace

// ============================================================================
//  Public API
// ============================================================================
DiffResult diff(const SystemSnapshot& prev, const SystemSnapshot& curr, const ScannerConfig& cfg) {
  DiffResult r;

  if (cfg.alertOnNewProcess)
    diffSuspiciousProcesses(prev, curr, r.newAlerts, r.currentKeys);

  if (cfg.alertOnNewPersistence)
    diffPersistence(prev, curr, r.newAlerts, r.currentKeys);

  // Cross-view findings ride under the kernel-extension master toggle for
  // now (both relate to "rootkit awareness"). We could split if needed.
  if (cfg.alertOnKernelExtensionChange) {
    diffCrossView(prev, curr, r.newAlerts, r.currentKeys);
    diffKernelExtensions(prev, curr, r.newAlerts, r.currentKeys);
  }

  if (cfg.alertOnIntegrityMismatch)
    diffIntegrity(prev, curr, r.newAlerts, r.currentKeys);

  return r;
}

}  // namespace SnapshotDiff
