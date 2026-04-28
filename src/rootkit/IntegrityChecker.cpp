// ============================================================================
// IntegrityChecker.cpp  –  baseline + verify, OS-version-aware
//
// Critical-path selection (macOS):
//   We hash a small, security-relevant, stable subset. Bigger sets become
//   noisy on every minor system update and dilute the signal. The bar is:
//     • the binary is part of macOS itself (not /Applications/*)
//     • compromise is high-impact (privilege boundary or trust anchor)
//     • the file changes only on OS updates (not on per-app updates)
//
//   /sbin/launchd, /usr/bin/sudo, /usr/bin/login, /usr/sbin/sshd,
//   /bin/launchctl, /usr/bin/codesign, /usr/bin/security
//
// On Apple Silicon, all of these are firm-linked into the Sealed System
// Volume. Reading them as a regular user works; modifying them is blocked
// by SIP. So a hash difference on the same OS version is either:
//   - SIP disabled and someone replaced the file (rare, very high signal)
//   - This tool is running on a non-stock build (jailbreak, custom kernel)
//   - The baseline was captured on a different macOS version we missed
//
// Storage format (odysseus_integrity_baseline.json):
//   {
//     "macos_version": "15.4",
//     "baselined_at":  "2026-04-27T18:00:00Z",
//     "entries": {
//       "/sbin/launchd": {
//         "sha256": "...", "size": 2218752,
//         "first_seen": "...", "last_verified": "..."
//       },
//       ...
//     }
//   }
//
// ============================================================================

#include "rootkit/IntegrityChecker.h"

#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QStandardPaths>
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDateTime>
#include <QProcess>
#include <QSysInfo>
#include <QDebug>
#include <QMutex>
#include <QMutexLocker>

namespace IntegrityChecker {

namespace {

// The curated path set. Order is informational only.
const QStringList& criticalPaths()
{
    static const QStringList paths = {
#if defined(Q_OS_MACOS)
        "/sbin/launchd",
        "/usr/bin/sudo",
        "/usr/bin/login",
        "/usr/sbin/sshd",
        "/bin/launchctl",
        "/usr/bin/codesign",
        "/usr/bin/security",
        // bash + zsh — frequently abused as droppers' final stage
        "/bin/bash",
        "/bin/zsh",
#elif defined(Q_OS_LINUX)
        "/usr/bin/sudo",
        "/usr/bin/su",
        "/usr/bin/passwd",
        "/usr/sbin/sshd",
        "/bin/login",
        "/bin/bash",
        "/usr/bin/zsh",
#elif defined(Q_OS_WIN)
        // Minimal Windows set. These DO change with monthly Patch Tuesday
        // updates, so the OS-version-string auto-rebase below handles it.
        // Mismatches under the same OS version flag tampering / SFC drift.
        "C:\\Windows\\System32\\kernel32.dll",
        "C:\\Windows\\System32\\ntdll.dll",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\explorer.exe",
#else
        // empty fallback
#endif
    };
    return paths;
}

QMutex g_baselineMutex;     // serializes baseline file read/write across threads

QString resolveBaselinePath()
{
    static QString cached;
    if (!cached.isEmpty()) return cached;
    const QString dir = QStandardPaths::writableLocation(
                            QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    cached = QDir(dir).absoluteFilePath("odysseus_integrity_baseline.json");
    return cached;
}

// Returns a stable OS version string — the auto-rebase logic uses it as the
// "did the OS update?" sentinel. Function is named "readMacosVersion" for
// historical reasons but now covers every supported platform.
QString readMacosVersion()
{
#if defined(Q_OS_MACOS)
    QProcess p;
    p.start("/usr/bin/sw_vers", { "-productVersion" });
    if (!p.waitForStarted(1000)) return {};
    if (!p.waitForFinished(2000)) { p.kill(); return {}; }
    return QString::fromUtf8(p.readAllStandardOutput()).trimmed();
#elif defined(Q_OS_LINUX)
    QFile f("/etc/os-release");
    if (f.open(QIODevice::ReadOnly)) {
        const QString text = QString::fromUtf8(f.readAll());
        f.close();
        for (const QString& line : text.split('\n')) {
            if (line.startsWith("VERSION_ID="))
                return line.mid(QString("VERSION_ID=").size())
                            .remove('"').trimmed();
        }
    }
    return {};
#elif defined(Q_OS_WIN)
    // Qt's QSysInfo gives us a usable Windows version string ("10", "11",
    // and a kernel build number we can append for slightly tighter
    // rebase granularity).
    return QString("%1 (build %2)")
              .arg(QSysInfo::productVersion(),
                   QSysInfo::kernelVersion());
#else
    // Last-ditch: any Qt-supported platform we don't have a special case
    // for. Better than empty — at least the auto-rebase fires on a major
    // version bump.
    return QSysInfo::prettyProductName();
#endif
}

QString hashFile(const QString& path, qint64& sizeOut)
{
    sizeOut = 0;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};

    QCryptographicHash h(QCryptographicHash::Sha256);
    char buf[64 * 1024];
    qint64 total = 0;
    while (!f.atEnd()) {
        const qint64 n = f.read(buf, sizeof(buf));
        if (n < 0) { f.close(); return {}; }
        if (n == 0) break;
        h.addData(QByteArrayView(buf, static_cast<qsizetype>(n)));
        total += n;
    }
    f.close();
    if (total == 0) return {};
    sizeOut = total;
    return QString::fromLatin1(h.result().toHex()).toLower();
}

// ----------------------------------------------------------------------------
// Baseline JSON I/O
// ----------------------------------------------------------------------------
struct BaselineEntry {
    QString sha256;
    qint64  size = 0;
    QString firstSeen;
    QString lastVerified;
};
struct Baseline {
    QString                         macosVersion;
    QDateTime                       baselinedAt;
    QHash<QString, BaselineEntry>   entries;
    bool                            existsOnDisk = false;
};

Baseline loadBaseline()
{
    Baseline b;
    QFile f(resolveBaselinePath());
    if (!f.exists()) return b;

    if (!f.open(QIODevice::ReadOnly)) {
        qWarning().noquote()
            << "[Integrity] cannot read baseline" << f.fileName()
            << "(" << f.errorString() << ") — treating as first run";
        return b;
    }
    const QByteArray data = f.readAll();
    f.close();

    QJsonParseError err;
    const QJsonDocument doc = QJsonDocument::fromJson(data, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        qWarning().noquote()
            << "[Integrity] baseline JSON corrupt (" << err.errorString()
            << ") — treating as first run";
        return b;
    }

    b.existsOnDisk = true;
    const QJsonObject root = doc.object();
    b.macosVersion = root.value("macos_version").toString();
    b.baselinedAt  = QDateTime::fromString(
                        root.value("baselined_at").toString(), Qt::ISODate);

    const QJsonObject entries = root.value("entries").toObject();
    for (auto it = entries.constBegin(); it != entries.constEnd(); ++it) {
        BaselineEntry e;
        const QJsonObject o = it.value().toObject();
        e.sha256       = o.value("sha256").toString();
        e.size         = static_cast<qint64>(o.value("size").toDouble());
        e.firstSeen    = o.value("first_seen").toString();
        e.lastVerified = o.value("last_verified").toString();
        b.entries.insert(it.key(), e);
    }
    return b;
}

bool saveBaseline(const Baseline& b)
{
    QJsonObject root;
    root["macos_version"] = b.macosVersion;
    root["baselined_at"]  = b.baselinedAt.toString(Qt::ISODate);

    QJsonObject entries;
    for (auto it = b.entries.constBegin(); it != b.entries.constEnd(); ++it) {
        QJsonObject o;
        o["sha256"]        = it.value().sha256;
        o["size"]          = double(it.value().size);
        o["first_seen"]    = it.value().firstSeen;
        o["last_verified"] = it.value().lastVerified;
        entries[it.key()]  = o;
    }
    root["entries"] = entries;

    QFile f(resolveBaselinePath());
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning().noquote()
            << "[Integrity] cannot write baseline:" << f.errorString();
        return false;
    }
    f.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    f.close();
    return true;
}

}  // anonymous

// ============================================================================
// Public API
// ============================================================================
QString baselinePath() { return resolveBaselinePath(); }

bool verify(QVector<IntegrityFinding>& out,
            int& checkedOut,
            int& mismatchOut,
            bool& baselineCreatedOut,
            bool& baselineRebasedOut,
            QString& macosVersionOut)
{
    QMutexLocker lock(&g_baselineMutex);

    checkedOut         = 0;
    mismatchOut        = 0;
    baselineCreatedOut = false;
    baselineRebasedOut = false;

    const QString currentVersion = readMacosVersion();
    macosVersionOut = currentVersion;

    Baseline baseline = loadBaseline();
    const bool firstRun = !baseline.existsOnDisk;
    const bool osChanged = baseline.existsOnDisk
                            && !baseline.macosVersion.isEmpty()
                            && !currentVersion.isEmpty()
                            && baseline.macosVersion != currentVersion;

    // OS version changed → silently rebase. We still hash everything; we
    // just won't flag mismatches. Drop all old entries.
    if (osChanged) {
        qInfo().noquote()
            << QString("[Integrity] macOS version changed (%1 → %2) — "
                       "rebasing integrity baseline silently")
                  .arg(baseline.macosVersion).arg(currentVersion);
        baseline.entries.clear();
        baseline.existsOnDisk = false;
        baselineRebasedOut = true;
    }

    if (firstRun) {
        qInfo().noquote()
            << "[Integrity] no baseline on disk — capturing first-run baseline";
        baselineCreatedOut = true;
    }

    const QString nowIso = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
    Baseline updated = baseline;
    updated.macosVersion = currentVersion;
    if (firstRun || osChanged)
        updated.baselinedAt = QDateTime::currentDateTimeUtc();
    else if (!updated.baselinedAt.isValid())
        updated.baselinedAt = QDateTime::currentDateTimeUtc();

    int mismatchCount = 0;
    int newCount      = 0;
    int missingCount  = 0;
    int okCount       = 0;

    for (const QString& path : criticalPaths()) {
        IntegrityFinding f;
        f.path = path;

        if (!QFileInfo::exists(path)) {
            // Path doesn't exist on this system — note it but don't escalate
            // (e.g. /usr/sbin/sshd might be missing on a desktop install).
            f.status   = "missing";
            f.severity = "medium";
            f.note     = "Path does not exist on this system";
            updated.entries.remove(path);
            ++missingCount;
            out.append(std::move(f));
            continue;
        }

        qint64 sz = 0;
        const QString hex = hashFile(path, sz);
        if (hex.isEmpty()) {
            f.status   = "missing";
            f.severity = "medium";
            f.note     = "Could not read file (permission denied or empty)";
            ++missingCount;
            out.append(std::move(f));
            continue;
        }

        f.currentHash = hex;
        f.currentSize = sz;
        ++checkedOut;

        const auto it = baseline.entries.constFind(path);
        if (it == baseline.entries.constEnd()) {
            // New entry — not in baseline yet. On first run we create it
            // silently; on subsequent runs we still log it as informational.
            f.status     = "new";
            f.severity   = "low";
            f.note       = firstRun
                           ? "Initial baseline entry"
                           : "New file added to baseline";
            BaselineEntry e;
            e.sha256       = hex;
            e.size         = sz;
            e.firstSeen    = nowIso;
            e.lastVerified = nowIso;
            updated.entries.insert(path, e);
            ++newCount;
            out.append(std::move(f));
            continue;
        }

        const BaselineEntry& prior = it.value();
        f.expectedHash = prior.sha256;

        if (prior.sha256 == hex) {
            f.status   = "ok";
            f.severity = "low";
            f.note     = "Hash matches baseline";
            // bump last_verified
            BaselineEntry e   = prior;
            e.lastVerified    = nowIso;
            updated.entries[path] = e;
            ++okCount;
            out.append(std::move(f));
            continue;
        }

        // Hash differs and OS version is unchanged → INTEGRITY VIOLATION.
        if (osChanged) {
            // We're in the silent-rebase path; just record the new hash.
            f.status   = "rebased";
            f.severity = "low";
            f.note     = "Hash updated as part of OS-version rebase";
            BaselineEntry e   = prior;
            e.sha256          = hex;
            e.size            = sz;
            e.lastVerified    = nowIso;
            updated.entries[path] = e;
            out.append(std::move(f));
            continue;
        }

        f.status   = "mismatch";
        f.severity = "high";
        f.note     = QString("SHA-256 differs from baseline. Possible tampering, "
                             "filesystem corruption, or out-of-band update.");
        ++mismatchCount;
        // Do NOT auto-update the baseline on a mismatch — leave it as evidence.
        out.append(std::move(f));
    }

    mismatchOut = mismatchCount;

    // Persist the updated baseline (covers first-run creation, rebase,
    // last_verified bumps, and new-path insertion).
    if (!saveBaseline(updated)) {
        qWarning() << "[Integrity] baseline save failed — findings are valid "
                      "but next run will re-hash everything";
    }

    qInfo().noquote()
        << QString("[Integrity] checked=%1 ok=%2 new=%3 missing=%4 mismatches=%5%6%7")
              .arg(checkedOut)
              .arg(okCount)
              .arg(newCount)
              .arg(missingCount)
              .arg(mismatchCount)
              .arg(firstRun  ? " [first-run]" : "")
              .arg(osChanged ? " [os-rebased]" : "");

    return true;
}

int forceRebase()
{
    QMutexLocker lock(&g_baselineMutex);

    Baseline updated;
    updated.macosVersion = readMacosVersion();
    updated.baselinedAt  = QDateTime::currentDateTimeUtc();
    const QString nowIso = updated.baselinedAt.toString(Qt::ISODate);

    for (const QString& path : criticalPaths()) {
        if (!QFileInfo::exists(path)) continue;
        qint64 sz = 0;
        const QString hex = hashFile(path, sz);
        if (hex.isEmpty()) continue;

        BaselineEntry e;
        e.sha256       = hex;
        e.size         = sz;
        e.firstSeen    = nowIso;
        e.lastVerified = nowIso;
        updated.entries.insert(path, e);
    }
    saveBaseline(updated);
    qInfo().noquote()
        << QString("[Integrity] force-rebased baseline with %1 entries")
              .arg(updated.entries.size());
    return updated.entries.size();
}

}  // namespace IntegrityChecker
