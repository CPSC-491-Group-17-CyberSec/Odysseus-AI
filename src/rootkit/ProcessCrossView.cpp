// ============================================================================
// ProcessCrossView.cpp
//
// Severity heuristic:
//   • If both sides agree on every PID → no findings.
//   • For each PID present in only one side:
//       - 1–2 mismatches total           → low ("normal process churn")
//       - 3–9 mismatches total            → medium
//       - 10+ mismatches                  → high (one side is being lied to)
//
// We deliberately don't try to be smart per-PID. A single dropper hidden
// from `ps` would still fall under the "low" bucket if no other churn is
// happening, which is correct: a single transient mismatch is hard to
// distinguish from short-lived processes. The user can re-run the check
// to see if it persists.
// ============================================================================

#include "rootkit/ProcessCrossView.h"

#include <QProcess>
#include <QSet>
#include <QHash>
#include <QStringList>
#include <QRegularExpression>
#include <QDebug>

namespace ProcessCrossView {

namespace {

struct ToolResult { int rc = -1; QString out; QString err; bool timedOut = false; };

ToolResult runTool(const QString& program, const QStringList& args, int msec = 4000)
{
    ToolResult r;
    QProcess p;
    p.start(program, args);
    if (!p.waitForStarted(1500)) return r;
    if (!p.waitForFinished(msec)) {
        p.kill();
        p.waitForFinished(500);
        r.timedOut = true;
        return r;
    }
    r.rc  = p.exitCode();
    r.out = QString::fromUtf8(p.readAllStandardOutput());
    r.err = QString::fromUtf8(p.readAllStandardError());
    return r;
}

// Parse `ps -axo pid=,comm=` output into a (pid → name) map.
// `=` after column names suppresses the header.
QHash<int, QString> parsePsOutput(const QString& output)
{
    QHash<int, QString> map;
    for (const QString& line : output.split('\n')) {
        const QString trimmed = line.trimmed();
        if (trimmed.isEmpty()) continue;

        const QStringList parts = trimmed.split(QRegularExpression("\\s+"),
                                                 Qt::SkipEmptyParts);
        if (parts.size() < 2) continue;

        bool ok = false;
        const int pid = parts.first().toInt(&ok);
        if (!ok || pid <= 0) continue;

        // The COMM column may contain spaces in extreme cases (rare). Join
        // everything after the PID for safety.
        const QString name = parts.mid(1).join(' ');
        map.insert(pid, name);
    }
    return map;
}

}  // anonymous

bool diff(const QVector<ProcessInfo>& existing,
          QVector<CrossViewFinding>&   out,
          int& sysctlCountOut,
          int& psCountOut)
{
    sysctlCountOut = 0;
    psCountOut     = 0;

#if defined(Q_OS_MACOS)
    // ── Source A: existing sysctl list (already in hand) ────────────────
    QHash<int, QString> sysctlMap;
    sysctlMap.reserve(existing.size());
    for (const ProcessInfo& p : existing)
        sysctlMap.insert(p.pid, p.name);
    sysctlCountOut = sysctlMap.size();

    // ── Source B: ps ────────────────────────────────────────────────────
    const ToolResult t = runTool("/bin/ps", { "-axo", "pid=,comm=" });
    if (t.timedOut || t.rc != 0 || t.out.isEmpty()) {
        qWarning().noquote()
            << "[Rootkit] ps -axo failed (rc=" << t.rc
            << ") — cross-view check skipped";
        return false;
    }
    const QHash<int, QString> psMap = parsePsOutput(t.out);
    psCountOut = psMap.size();

    // ── Diff ───────────────────────────────────────────────────────────
    QVector<CrossViewFinding> findings;

    for (auto it = sysctlMap.constBegin(); it != sysctlMap.constEnd(); ++it) {
        if (!psMap.contains(it.key())) {
            CrossViewFinding f;
            f.pid       = it.key();
            f.name      = it.value();
            f.visibleIn = "sysctl-only";
            f.reason    = QString("PID %1 (%2) appears in sysctl but is missing "
                                   "from `ps` output — possible userland process "
                                   "hiding, or the process exited between snapshots")
                              .arg(it.key()).arg(it.value());
            findings.append(std::move(f));
        }
    }
    for (auto it = psMap.constBegin(); it != psMap.constEnd(); ++it) {
        if (!sysctlMap.contains(it.key())) {
            CrossViewFinding f;
            f.pid       = it.key();
            f.name      = it.value();
            f.visibleIn = "ps-only";
            f.reason    = QString("PID %1 (%2) appears in `ps` but is missing "
                                   "from sysctl — possible kernel-side hiding, "
                                   "or the process started between snapshots")
                              .arg(it.key()).arg(it.value());
            findings.append(std::move(f));
        }
    }

    // ── Severity by total mismatch count ───────────────────────────────
    QString sev;
    if      (findings.size() >= 10) sev = "high";
    else if (findings.size() >= 3)  sev = "medium";
    else                             sev = "low";

    for (auto& f : findings) f.severity = sev;
    out.append(findings);

    qInfo().noquote()
        << QString("[Rootkit] cross-view: %1 sysctl PIDs vs %2 ps PIDs — "
                   "%3 disagreement(s) [%4]")
              .arg(sysctlCountOut).arg(psCountOut)
              .arg(findings.size()).arg(sev);
    return true;

#else
    // Linux/other: no second authoritative source distinct from /proc.
    Q_UNUSED(existing)
    qInfo() << "[Rootkit] cross-view check is macOS-only — skipping on this platform";
    return false;
#endif
}

}  // namespace ProcessCrossView
