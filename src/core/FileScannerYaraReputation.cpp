// ============================================================================
// FileScannerYaraReputation.cpp  –  Phase 1 detection passes
//
// Glue layer that wires the YARA scanner and the reputation database into
// the FileScanner pipeline. Mirrors the singleton pattern used by
// FileScannerDetectors.cpp (the AI pass): one global YR_RULES set and one
// global ReputationDB shared by all worker threads.
//
// Flow inside runHashWorker():
//
//      File ──> [hash pass]  ──hit──> SuspiciousFile (family from rep DB)
//                  │
//                  └─miss/exempt──> [YARA pass] ──hit──> SuspiciousFile (rule names)
//                                       │
//                                       └─miss──> [AI pass] (existing checkByAI)
//
// The YARA pass is cheap (~1 ms per file once rules are compiled), so we
// run it on every uncached file regardless of extension. We DO skip files
// over 100 MB to avoid runaway memory use on bloated installers.
// ============================================================================

#include "FileScanner.h"
#include "scanner/YaraScanner.h"
#include "reputation/ReputationDB.h"
#include "reputation/CodeSigning.h"
#include "core/ScannerConfig.h"

#include <QCoreApplication>
#include <QFileInfo>
#include <QStandardPaths>
#include <QDir>
#include <QMutex>
#include <QMutexLocker>
#include <QDebug>

// ============================================================================
// Singletons – lazy-initialized, shared across worker threads
// ============================================================================
namespace {

QMutex          g_initMutex;
bool            g_yaraInitDone = false;
ReputationDB*   g_repDb        = nullptr;
bool            g_repDbInitDone = false;

QString findRulesDir(const QString& appDir)
{
    const QStringList candidates = {
        appDir + "/data/yara_rules",
        appDir + "/../data/yara_rules",
        appDir + "/../../data/yara_rules",
        appDir + "/../../../data/yara_rules",
    };
    for (const QString& p : candidates)
        if (QFileInfo::exists(p)) return p;
    return {};
}

QString findSeedFile(const QString& appDir)
{
    const QStringList candidates = {
        appDir + "/data/malware_hashes.txt",
        appDir + "/../data/malware_hashes.txt",
        appDir + "/../../data/malware_hashes.txt",
        appDir + "/../../../data/malware_hashes.txt",
    };
    for (const QString& p : candidates)
        if (QFileInfo::exists(p)) return p;
    return {};
}

void ensureYaraInitialized()
{
    QMutexLocker lock(&g_initMutex);
    if (g_yaraInitDone) return;
    g_yaraInitDone = true;       // mark even on failure to avoid retry storms

    const ScannerConfig& cfg = ScannerConfigStore::current();

    if (!cfg.yaraEnabled) {
        qInfo().noquote()
            << "[YARA] disabled in configuration "
               "(set yaraEnabled=true in odysseus_config.json to enable)";
        return;
    }

    const QString appDir   = QCoreApplication::applicationDirPath();
    const QString rulesDir = findRulesDir(appDir);
    if (rulesDir.isEmpty()) {
        qWarning().noquote()
            << "[YARA] no yara_rules directory found near" << appDir
            << "— YARA pass will be a no-op (expected at <appDir>/data/yara_rules)";
        return;
    }

    YaraInitOptions opts;
    opts.rulesDir            = rulesDir;
    opts.includeExperimental = cfg.experimentalRules;
    opts.experimentalSubdir  = cfg.experimentalSubdir;
    opts.maxCompileErrors    = cfg.maxCompileErrors;
    opts.verbose             = cfg.verboseLogging;

    YaraScanner::initialize(opts);
    // YaraScanner::initialize logs its own success/failure summary already.
}

ReputationDB* getReputationDB()
{
    QMutexLocker lock(&g_initMutex);
    if (g_repDbInitDone) return g_repDb;
    g_repDbInitDone = true;

    const QString dataDir = QStandardPaths::writableLocation(
                                QStandardPaths::AppDataLocation);
    const QString seed    = findSeedFile(QCoreApplication::applicationDirPath());

    auto* db = new ReputationDB();
    if (!db->open(dataDir, seed)) {
        delete db;
        qWarning().noquote()
            << "[Reputation] FAILED to open DB at" << dataDir
            << "— scanner will run without reputation enrichment.\n"
            << "             Common causes: read-only home directory, "
               "AppDataLocation unwritable, or sqlite I/O error.";
        return nullptr;
    }

    g_repDb = db;
    const int rows = db->rowCount();
    qInfo().noquote()
        << QString("[Reputation] DB ready at %1 — %2 row(s) loaded%3")
              .arg(db->path())
              .arg(rows)
              .arg(seed.isEmpty()
                       ? QStringLiteral(" (no seed file found)")
                       : QString(" (seed: %1)").arg(seed));
    if (rows == 0 && seed.isEmpty()) {
        qWarning().noquote()
            << "[Reputation] DB is empty and no seed file was found. "
               "Hash-pass detection will not catch known samples until you "
               "either run scans (which auto-populate flagged hashes) or drop "
               "a malware_hashes.txt seed under data/.";
    }
    return g_repDb;
}

}  // anonymous namespace

// ============================================================================
// External helper used by FileScannerHash.cpp
// We expose it via this name so the existing TU can reuse it without pulling
// the full singleton initialization into its compile unit.
// ============================================================================
ReputationDB* odysseus_getReputationDB() { return getReputationDB(); }

// ============================================================================
// checkByYara
//
// Returns true if any rule fired. Populates outDetails->yaraMatches /
// yaraFamily / yaraSeverity / classificationLevel.
//
// Severity mapping (rule meta `severity=`):
//   critical → CRITICAL
//   high     → Suspicious
//   medium   → Anomalous
//   low      → Anomalous (kept; the user can review)
// ============================================================================
bool checkByYara(const QString& filePath,
                 qint64         fileSize,
                 QString&       outReason,
                 QString&       outCategory,
                 SuspiciousFile* outDetails)
{
    // Files larger than 100 MB are skipped — same cap as the AI pass. YARA
    // can scan them, but the cost vs. signal trade-off isn't worth it.
    if (fileSize <= 0 || fileSize > 100LL * 1024 * 1024)
        return false;

    ensureYaraInitialized();
    if (!YaraScanner::isAvailable())
        return false;

    YaraScanResult yr = YaraScanner::scanFile(filePath);
    if (yr.hadError || !yr.fired())
        return false;

    // Determine the worst severity across all matches
    auto sevRank = [](const QString& s) -> int {
        const QString t = s.toLower();
        if (t == "critical") return 4;
        if (t == "high")     return 3;
        if (t == "medium")   return 2;
        if (t == "low")      return 1;
        return 0;
    };

    int worstRank = 0;
    QString worstSev;
    QString primaryFamily;
    QStringList ruleNames;

    for (const YaraMatch& m : yr.matches) {
        ruleNames.append(m.ruleName);
        const int r = sevRank(m.severity);
        if (r > worstRank) {
            worstRank = r;
            worstSev  = m.severity;
        }
        if (primaryFamily.isEmpty() && !m.family.isEmpty())
            primaryFamily = m.family;
    }

    // Map worst YARA severity → existing classification levels
    QString classification;
    QString severity;
    if (worstRank >= 4)      { classification = "Critical";   severity = "CRITICAL"; }
    else if (worstRank == 3) { classification = "Suspicious"; severity = "High";     }
    else                     { classification = "Anomalous";  severity = "Medium";   }

    outCategory = "YARA Rule Match";
    outReason   = QString("YARA rule(s) fired: %1\nFamily: %2\nSeverity: %3")
                      .arg(ruleNames.join(", "),
                           primaryFamily.isEmpty() ? QStringLiteral("(unspecified)")
                                                   : primaryFamily,
                           worstSev.isEmpty() ? QStringLiteral("medium") : worstSev);

    if (outDetails) {
        outDetails->yaraMatches        = ruleNames;
        outDetails->yaraFamily         = primaryFamily;
        outDetails->yaraSeverity       = worstSev.isEmpty() ? "medium" : worstSev;
        outDetails->classificationLevel = classification;
        outDetails->severityLevel      = severity;
        // YARA matches are deterministic — give a high default confidence
        // (caller may overwrite with anomalyScore if AI also fires).
        outDetails->confidencePct      = (worstRank >= 4) ? 95.0f
                                       : (worstRank >= 3) ? 85.0f
                                       : (worstRank >= 2) ? 70.0f
                                                          : 55.0f;
    }
    return true;
}
