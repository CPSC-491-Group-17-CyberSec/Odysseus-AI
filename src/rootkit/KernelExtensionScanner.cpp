// ============================================================================
// KernelExtensionScanner.cpp
//
// Parsing strategy:
//   Apple's tools emit human-formatted output that changes between OS
//   versions. We parse defensively: extract the fields we recognize,
//   skip lines we don't understand, and never let one weird line abort
//   the whole pass.
//
// systemextensionsctl list  (macOS Big Sur+):
//   1 extension(s)
//   --- com.apple.system_extension.endpoint_security
//   enabled  active  teamID    bundleID (version)              name              [state]
//   *        *       1234ABCDE  com.example.endpoint (1.2.3/100) Example Endpoint  [activated
//   enabled]
//
// kmutil showloaded:
//   Index Refs Address           Size        Wired       Name (Version) UUID <Linked Against>
//   1     156  0xfffffe...        0x1000000   0x1000000   com.apple.kpi.bsd (8.0.0) ...
//
// We extract:
//   • bundleId (com.apple.kpi.bsd, com.example.driver, etc.)
//   • teamId   (10-char Apple Developer ID)
//   • version
//   • state    (activated, enabled, loaded, ...)
// And mark anything outside the known-Apple-bundle-prefix set for review.
// ============================================================================

#include "rootkit/KernelExtensionScanner.h"

#include <QDebug>
#include <QFile>
#include <QProcess>
#include <QRegularExpression>
#include <QString>
#include <QStringList>

namespace KernelExtensionScanner {

namespace {

struct ToolResult {
  int rc = -1;
  QString out;
  QString err;
  bool timedOut = false;
};

ToolResult runTool(const QString& program, const QStringList& args, int msec = 6000) {
  ToolResult r;
  QProcess p;
  p.start(program, args);
  if (!p.waitForStarted(2000))
    return r;
  if (!p.waitForFinished(msec)) {
    p.kill();
    p.waitForFinished(500);
    r.timedOut = true;
    return r;
  }
  r.rc = p.exitCode();
  r.out = QString::fromUtf8(p.readAllStandardOutput());
  r.err = QString::fromUtf8(p.readAllStandardError());
  return r;
}

bool looksLikeAppleBundle(const QString& bundleId) {
  return bundleId.startsWith("com.apple.") || bundleId.startsWith("com.apple") ||
         bundleId.startsWith("apple.");
}

void rateExtension(KernelExtension& k) {
  // Severity grading: Apple extensions are baseline noise, suspect anything
  // whose pedigree we can't cleanly attribute.
  if (k.isApple) {
    k.severity = "low";
    return;
  }
  bool unsignedHint = false;
  for (const QString& n : k.notes) {
    if (n.contains("unsigned", Qt::CaseInsensitive) || n.contains("ad hoc", Qt::CaseInsensitive))
      unsignedHint = true;
  }
  if (k.teamId.isEmpty() || unsignedHint) {
    k.severity = "high";
    if (k.teamId.isEmpty())
      k.notes.append("No Apple Developer Team ID associated");
    return;
  }
  // Has a team ID, signed, but not Apple. Worth surfacing.
  k.severity = "medium";
  k.notes.append("Non-Apple kernel/system extension — review for legitimacy");
}

}  // namespace

// ============================================================================
// macOS implementation
// ============================================================================
#if defined(Q_OS_MACOS)

// systemextensionsctl list parser.
// Each "section" begins with a line of dashes, then a header line, then rows.
// We treat any row that starts with "*" or contains a long bundle-id as a row.
static void parseSystemExtensions(const QString& output, QVector<KernelExtension>& out) {
  int found = 0;
  static const QRegularExpression rowRx(
      // Capture: enabled  active  teamID  bundleID (version)  name  [state]
      // We take a relaxed approach: split by 2+ spaces.
      R"(^\s*([\*\-])\s+([\*\-])\s+([A-Z0-9]{6,})\s+([A-Za-z0-9_.\-]+)\s+\(([^)]+)\)\s+(.+?)\s+\[([^\]]+)\]\s*$)",
      QRegularExpression::MultilineOption);

  auto it = rowRx.globalMatch(output);
  while (it.hasNext()) {
    auto m = it.next();
    KernelExtension k;
    k.source = "system_extension";
    k.isUserspace = true;  // SEs run in userspace, not kernel
    // m.captured(1) = enabled flag, m.captured(2) = active flag — informational
    k.teamId = m.captured(3).trimmed();
    k.bundleId = m.captured(4).trimmed();
    k.version = m.captured(5).trimmed();
    k.name = m.captured(6).trimmed();
    k.state = m.captured(7).trimmed();
    k.signedBy = QString("TeamID:%1").arg(k.teamId);
    k.isApple =
        (k.teamId == "APPLE" || k.teamId == "0000000000") || looksLikeAppleBundle(k.bundleId);
    rateExtension(k);
    out.append(std::move(k));
    ++found;
  }
  qInfo().noquote() << QString("[Rootkit] system_extension(s) parsed: %1").arg(found);
}

// kmutil showloaded parser.
// We only need the bundle name field — the rest is bookkeeping.
static void parseKmutilShowloaded(const QString& output, QVector<KernelExtension>& out) {
  int found = 0;
  int skipped = 0;
  bool sawHeader = false;

  for (const QString& line : output.split('\n')) {
    const QString trimmed = line.trimmed();
    if (trimmed.isEmpty())
      continue;
    if (trimmed.startsWith("Executing:"))
      continue;

    // Detect and skip the header row containing "Index" and "Name"
    if (!sawHeader && trimmed.startsWith("Index")) {
      sawHeader = true;
      continue;
    }
    if (!sawHeader)
      continue;  // ignore preamble

    // Columns: Index Refs Address Size Wired Name (Version) ...
    // We split on whitespace and take everything from column 5 onwards.
    const QStringList parts = trimmed.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
    if (parts.size() < 6) {
      ++skipped;
      continue;
    }

    // The 6th column onward contains "name (version) UUID <link list>"
    const QString rest = parts.mid(5).join(' ');
    const QRegularExpression nameRx(R"(^([A-Za-z0-9_.\-]+)\s*\(([^)]+)\))");
    const auto m = nameRx.match(rest);
    if (!m.hasMatch()) {
      ++skipped;
      continue;
    }

    KernelExtension k;
    k.source = "legacy_kext";
    k.isUserspace = false;  // legacy kexts ARE kernel-resident
    k.bundleId = m.captured(1).trimmed();
    k.version = m.captured(2).trimmed();
    k.name = k.bundleId;
    k.state = "loaded";
    k.isApple = looksLikeAppleBundle(k.bundleId);
    if (k.isApple)
      k.signedBy = "Apple";
    // kmutil doesn't expose team ID directly without --signing-info; keep
    // it empty so non-Apple kexts get medium/high severity.
    rateExtension(k);
    out.append(std::move(k));
    ++found;
  }
  qInfo().noquote() << QString(
                           "[Rootkit] legacy_kext(s) parsed: %1 (skipped %2 unparseable line(s))")
                           .arg(found)
                           .arg(skipped);
}

bool list(QVector<KernelExtension>& out, int& totalsOut) {
  bool anyOk = false;

  // ── System Extensions (DriverKit / EndpointSecurity / NetworkExtension) ─
  {
    const ToolResult t = runTool("/usr/bin/systemextensionsctl", {"list"});
    if (t.timedOut) {
      qWarning() << "[Rootkit] systemextensionsctl timed out — skipping system extensions";
    } else if (t.rc != 0) {
      qWarning().noquote() << "[Rootkit] systemextensionsctl returned" << t.rc
                           << "— skipping system extensions";
    } else if (t.out.contains("0 extension", Qt::CaseInsensitive)) {
      qInfo() << "[Rootkit] no system extensions installed";
      anyOk = true;
    } else {
      parseSystemExtensions(t.out, out);
      anyOk = true;
    }
  }

  // ── Legacy kexts (kmutil) ──────────────────────────────────────────
  {
    const ToolResult t = runTool("/usr/bin/kmutil", {"showloaded"});
    if (t.timedOut) {
      qWarning() << "[Rootkit] kmutil showloaded timed out — skipping legacy kexts";
    } else if (t.rc != 0) {
      qWarning().noquote() << "[Rootkit] kmutil showloaded returned" << t.rc
                           << "— skipping legacy kexts";
    } else {
      parseKmutilShowloaded(t.out, out);
      anyOk = true;
    }
  }

  totalsOut = out.size();
  return anyOk;
}

// ============================================================================
// Linux implementation
// ============================================================================
#elif defined(Q_OS_LINUX)

bool list(QVector<KernelExtension>& out, int& totalsOut) {
  QFile f("/proc/modules");
  if (!f.open(QIODevice::ReadOnly)) {
    qWarning() << "[Rootkit] cannot open /proc/modules";
    totalsOut = 0;
    return false;
  }
  const QString text = QString::fromUtf8(f.readAll());
  f.close();

  int n = 0;
  for (const QString& line : text.split('\n')) {
    const QString trimmed = line.trimmed();
    if (trimmed.isEmpty())
      continue;

    // Format: "<name> <size> <usedby_count> <usedby_list> <state> <addr>"
    const QStringList parts = trimmed.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
    if (parts.isEmpty())
      continue;

    KernelExtension k;
    k.source = "linux_module";
    k.isUserspace = false;
    k.bundleId = parts[0];
    k.name = parts[0];
    k.state = (parts.size() >= 5) ? parts[4] : "loaded";
    // No signing info available from /proc/modules alone; would need
    // `modinfo <name>` + signature parsing. Skipped for Phase 3.
    k.notes.append("Signing status not verified (Linux scaffold)");
    // Default to medium for everything since we can't easily classify
    rateExtension(k);
    if (k.severity == "low")
      k.severity = "medium";
    out.append(std::move(k));
    ++n;
  }
  totalsOut = n;
  qInfo().noquote() << QString("[Rootkit] linux_module(s): %1").arg(n);
  return true;
}

// ============================================================================
// Windows stub (kernel driver enumeration deferred)
// ============================================================================
#elif defined(Q_OS_WIN)

bool list(QVector<KernelExtension>& /*out*/, int& totalsOut) {
  totalsOut = 0;
  qInfo() << "[Rootkit] Windows kernel driver inspection not implemented yet — "
             "(planned: EnumDeviceDrivers / Service Control Manager filter).";
  return false;
}

// ============================================================================
// Other-platform stub
// ============================================================================
#else

bool list(QVector<KernelExtension>& /*out*/, int& totalsOut) {
  totalsOut = 0;
  qInfo() << "[Rootkit] kernel-extension scan not implemented on this platform";
  return false;
}

#endif

}  // namespace KernelExtensionScanner
