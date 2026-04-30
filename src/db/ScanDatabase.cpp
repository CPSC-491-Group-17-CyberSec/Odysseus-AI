#include "ScanDatabase.h"

#include "sqlite3.h"
#include "db/CacheVersion.h"   // Phase 5 — model/rules/config invalidation

#include <QStandardPaths>
#include <QFileInfo>
#include <QDir>
#include <QFile>
#include <QCryptographicHash>
#include <QDebug>
#include <QMetaObject>

// ============================================================================
// Schema
// ============================================================================
//
//  scans          – one row per completed scan session
//  scan_findings  – one row per suspicious file found during a scan
//
// The "findings" table stores the minimum fields required by the report spec
// (file_path, file_size, last_modified, sha256_hash, scan_status) plus the
// fields already present in SuspiciousFile (reason, category, cve_id, etc.)
// so that the full ScanRecord can be reconstructed from the DB alone.
//
static const char* kCreateScansTable = R"sql(
CREATE TABLE IF NOT EXISTS scans (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp         TEXT    NOT NULL,
    total_scanned     INTEGER NOT NULL DEFAULT 0,
    suspicious_count  INTEGER NOT NULL DEFAULT 0,
    elapsed_seconds   INTEGER NOT NULL DEFAULT 0
);
)sql";

static const char* kCreateFindingsTable = R"sql(
CREATE TABLE IF NOT EXISTS scan_findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    file_path     TEXT    NOT NULL,
    file_name     TEXT    NOT NULL,
    file_size     INTEGER NOT NULL DEFAULT 0,
    last_modified TEXT,
    sha256_hash   TEXT,
    scan_status   TEXT    NOT NULL DEFAULT 'Detected',
    reason        TEXT,
    category      TEXT,
    cve_id        TEXT,
    cve_summary   TEXT,
    cve_severity  TEXT
);
)sql";

// Enable WAL mode and foreign keys for all new connections.
static const char* kCreateCacheTable = R"sql(
CREATE TABLE IF NOT EXISTS scan_cache (
    file_path             TEXT    PRIMARY KEY,
    last_modified         TEXT    NOT NULL,
    last_scanned_at       TEXT    NOT NULL,
    file_size             INTEGER NOT NULL DEFAULT 0,
    scan_result           TEXT    NOT NULL DEFAULT 'clean',
    reason                TEXT,
    category              TEXT,
    classification_level  TEXT,
    severity_level        TEXT,
    anomaly_score         REAL    DEFAULT 0,
    ai_summary            TEXT,
    key_indicators        TEXT,
    recommended_actions   TEXT
);
)sql";

// Migration: add new columns to an existing scan_cache table.
// ALTER TABLE … ADD COLUMN is idempotent in practice – we ignore errors
// when the column already exists.
static const char* kMigrateCacheColumns[] = {
    "ALTER TABLE scan_cache ADD COLUMN file_size             INTEGER NOT NULL DEFAULT 0;",
    "ALTER TABLE scan_cache ADD COLUMN scan_result           TEXT    NOT NULL DEFAULT 'clean';",
    "ALTER TABLE scan_cache ADD COLUMN reason                TEXT;",
    "ALTER TABLE scan_cache ADD COLUMN category              TEXT;",
    "ALTER TABLE scan_cache ADD COLUMN classification_level  TEXT;",
    "ALTER TABLE scan_cache ADD COLUMN severity_level        TEXT;",
    "ALTER TABLE scan_cache ADD COLUMN anomaly_score         REAL    DEFAULT 0;",
    "ALTER TABLE scan_cache ADD COLUMN ai_summary            TEXT;",
    "ALTER TABLE scan_cache ADD COLUMN key_indicators        TEXT;",
    "ALTER TABLE scan_cache ADD COLUMN recommended_actions   TEXT;",
    "ALTER TABLE scan_cache ADD COLUMN ai_explanation        TEXT;",
    "ALTER TABLE scan_cache ADD COLUMN llm_available         INTEGER DEFAULT 0;",
    // Phase 5 — cache versioning. NULL on existing rows → never matches a
    // current version → those rows are treated as stale and re-scanned.
    "ALTER TABLE scan_cache ADD COLUMN model_version         TEXT;",
    "ALTER TABLE scan_cache ADD COLUMN rules_version         TEXT;",
    "ALTER TABLE scan_cache ADD COLUMN config_hash           TEXT;",
    nullptr
};

// Key-value table for persistent scanner state (e.g. last scan root).
static const char* kCreateStateTable = R"sql(
CREATE TABLE IF NOT EXISTS scan_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
)sql";

static const char* kPragmas = R"sql(
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous   = NORMAL;
)sql";

// ============================================================================
// Helpers
// ============================================================================
namespace {

// Run a single SQL statement; returns true on success.
bool execSql(sqlite3* db, const char* sql, QString* errOut = nullptr)
{
    char* errmsg = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        QString msg = QString("SQLite error: %1  [SQL: %2]")
                          .arg(errmsg ? errmsg : "unknown")
                          .arg(sql);
        if (errOut)
            *errOut = msg;
        else
            qWarning() << msg;
        sqlite3_free(errmsg);
        return false;
    }
    return true;
}

// Bind a UTF-8 QString to a prepared statement parameter by index (1-based).
void bindText(sqlite3_stmt* stmt, int idx, const QString& val)
{
    QByteArray utf8 = val.toUtf8();
    sqlite3_bind_text(stmt, idx, utf8.constData(), utf8.size(), SQLITE_TRANSIENT);
}

void bindInt64(sqlite3_stmt* stmt, int idx, qint64 val)
{
    sqlite3_bind_int64(stmt, idx, static_cast<sqlite3_int64>(val));
}

void bindInt(sqlite3_stmt* stmt, int idx, int val)
{
    sqlite3_bind_int(stmt, idx, val);
}

} // anonymous namespace

// ============================================================================
// ScanDatabase – constructor / destructor
// ============================================================================
ScanDatabase::ScanDatabase(QObject* parent)
    : QObject(parent)
{
    // ------------------------------------------------------------------
    // Determine cross-platform database path:
    //   Windows  → %APPDATA%\Odysseus\odysseus.db
    //   macOS    → ~/Library/Application Support/Odysseus/odysseus.db
    //   Linux    → ~/.local/share/Odysseus/odysseus.db
    // ------------------------------------------------------------------
    QString dataDir = QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation
    );

    // AppLocalDataLocation uses the applicationName(); fall back to a
    // hard-coded subdir if Qt hasn't been given an app name yet.
    if (dataDir.isEmpty())
        dataDir = QDir::homePath() + "/.odysseus";

    QDir dir;
    if (!dir.mkpath(dataDir)) {
        qWarning() << "ScanDatabase: could not create data directory:" << dataDir;
    }

    m_dbPath = dataDir + "/odysseus.db";
    qDebug() << "ScanDatabase: using" << m_dbPath;

    // ------------------------------------------------------------------
    // Open a read-only (technically read-write, but we never write here)
    // connection for UI-thread queries.
    // ------------------------------------------------------------------
    if (!openDatabase(&m_readDb, m_dbPath)) {
        qWarning() << "ScanDatabase: could not open read connection to" << m_dbPath;
        m_readDb = nullptr;
    } else {
        createSchema(m_readDb);   // idempotent – creates tables if absent
    }

    // ------------------------------------------------------------------
    // Start the writer thread (opens its own exclusive write connection).
    // ------------------------------------------------------------------
    m_writerThread = new WriterThread(m_dbPath, this);
    m_writerThread->start();
}

ScanDatabase::~ScanDatabase()
{
    if (m_writerThread) {
        m_writerThread->requestStop();
        m_writerThread->wait(5000);
        delete m_writerThread;
        m_writerThread = nullptr;
    }

    if (m_readDb) {
        sqlite3_close(m_readDb);
        m_readDb = nullptr;
    }
}

// ============================================================================
// openDatabase
// ============================================================================
bool ScanDatabase::openDatabase(sqlite3** db, const QString& path) const
{
    QByteArray pathUtf8 = path.toUtf8();
    int rc = sqlite3_open_v2(
        pathUtf8.constData(),
        db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        nullptr
    );
    if (rc != SQLITE_OK) {
        qWarning() << "ScanDatabase: sqlite3_open_v2 failed for" << path
                   << "-" << sqlite3_errmsg(*db);
        sqlite3_close(*db);
        *db = nullptr;
        return false;
    }
    return true;
}

// ============================================================================
// createSchema  (idempotent – uses CREATE IF NOT EXISTS)
// ============================================================================
bool ScanDatabase::createSchema(sqlite3* db)
{
    QString err;
    if (!execSql(db, kPragmas, &err)) {
        qWarning() << "ScanDatabase::createSchema pragmas:" << err;
        // Non-fatal – continue
    }
    if (!execSql(db, kCreateScansTable, &err)) {
        qWarning() << "ScanDatabase::createSchema scans table:" << err;
        return false;
    }
    if (!execSql(db, kCreateFindingsTable, &err)) {
        qWarning() << "ScanDatabase::createSchema findings table:" << err;
        return false;
    }
    if (!execSql(db, kCreateCacheTable, &err)) {
        qWarning() << "ScanDatabase::createSchema cache table:" << err;
        return false;
    }
    // Migrate existing scan_cache tables that lack the v2 columns.
    // The "duplicate column name" error is EXPECTED on every run after
    // the first (the column already exists) — pass `&migrateErr` so
    // execSql doesn't log internally, then qWarning only on real errors.
    for (int i = 0; kMigrateCacheColumns[i]; ++i) {
        QString migrateErr;
        if (!execSql(db, kMigrateCacheColumns[i], &migrateErr)
            && !migrateErr.contains("duplicate column", Qt::CaseInsensitive))
        {
            qWarning().noquote() << migrateErr;
        }
    }

    if (!execSql(db, kCreateStateTable, &err)) {
        qWarning() << "ScanDatabase::createSchema state table:" << err;
        return false;
    }
    return true;
}

// ============================================================================
// computeSha256  –  pure Qt, no OpenSSL dependency at compile time
// ============================================================================
/*static*/ QString ScanDatabase::computeSha256(const QString& filePath)
{
    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly))
        return {};

    QCryptographicHash hash(QCryptographicHash::Sha256);

    // Read in 256 KB chunks – keeps memory flat for large files.
    constexpr int kChunkSize = 256 * 1024;
    while (!f.atEnd()) {
        QByteArray chunk = f.read(kChunkSize);
        if (chunk.isEmpty())
            break;
        hash.addData(chunk);
    }
    f.close();
    return QString::fromLatin1(hash.result().toHex());
}

// ============================================================================
// enqueueWrite  –  thread-safe enqueue
// ============================================================================
void ScanDatabase::enqueueWrite(DatabaseWriteTask task)
{
    if (m_writerThread)
        m_writerThread->enqueue(std::move(task));
}

// ============================================================================
// saveScanRecord  (async)
// ============================================================================
void ScanDatabase::saveScanRecord(const ScanRecord& record)
{
    // Capture a deep copy so the record survives asynchronously.
    ScanRecord copy = record;

    enqueueWrite([copy, this](sqlite3* db) {
        // ------------------------------------------------------------------
        // Insert the scan header row inside a single transaction.
        // The findings rows are also inserted in the same transaction so we
        // never have a scan header without its findings (or vice versa).
        // ------------------------------------------------------------------
        execSql(db, "BEGIN;");

        // -- Insert scan header --
        const char* scanSql =
            "INSERT INTO scans (timestamp, total_scanned, suspicious_count, elapsed_seconds) "
            "VALUES (?, ?, ?, ?);";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, scanSql, -1, &stmt, nullptr) != SQLITE_OK) {
            qWarning() << "saveScanRecord: prepare scan insert failed:"
                       << sqlite3_errmsg(db);
            execSql(db, "ROLLBACK;");
            return;
        }

        bindText (stmt, 1, copy.timestamp.toString(Qt::ISODate));
        bindInt  (stmt, 2, copy.totalScanned);
        bindInt  (stmt, 3, copy.suspiciousCount);
        bindInt  (stmt, 4, copy.elapsedSeconds);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            qWarning() << "saveScanRecord: step scan insert failed:"
                       << sqlite3_errmsg(db);
            sqlite3_finalize(stmt);
            execSql(db, "ROLLBACK;");
            return;
        }
        sqlite3_finalize(stmt);

        qint64 scanId = sqlite3_last_insert_rowid(db);

        // -- Insert each finding --
        const char* findingSql =
            "INSERT INTO scan_findings "
            "(scan_id, file_path, file_name, file_size, last_modified, "
            " sha256_hash, scan_status, reason, category, cve_id, cve_summary, cve_severity) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

        for (const SuspiciousFile& sf : copy.findings) {
            sqlite3_stmt* fstmt = nullptr;
            if (sqlite3_prepare_v2(db, findingSql, -1, &fstmt, nullptr) != SQLITE_OK) {
                qWarning() << "saveScanRecord: prepare finding insert failed:"
                           << sqlite3_errmsg(db);
                continue;
            }

            // Use the hash already computed by the scanner worker; fall back to
            // recomputing only if the field is somehow empty (manual report injection).
            QString hash = sf.sha256.isEmpty() ? computeSha256(sf.filePath) : sf.sha256;

            bindInt64(fstmt,  1, scanId);
            bindText (fstmt,  2, sf.filePath);
            bindText (fstmt,  3, sf.fileName);
            bindInt64(fstmt,  4, sf.sizeBytes);
            bindText (fstmt,  5, sf.lastModified.toString(Qt::ISODate));
            bindText (fstmt,  6, hash);
            bindText (fstmt,  7, QStringLiteral("Detected"));
            bindText (fstmt,  8, sf.reason);
            bindText (fstmt,  9, sf.category);
            bindText (fstmt, 10, sf.cveId);
            bindText (fstmt, 11, sf.cveSummary);
            bindText (fstmt, 12, sf.cveSeverity);

            if (sqlite3_step(fstmt) != SQLITE_DONE) {
                qWarning() << "saveScanRecord: step finding insert failed:"
                           << sqlite3_errmsg(db);
            }
            sqlite3_finalize(fstmt);
        }

        execSql(db, "COMMIT;");

        // Notify UI thread.
        QMetaObject::invokeMethod(this, [this, scanId]() {
            emit recordSaved(scanId);
        }, Qt::QueuedConnection);
    });
}

// ============================================================================
// loadAllScanRecords  (synchronous, UI thread)
// ============================================================================
QVector<ScanRecord> ScanDatabase::loadAllScanRecords() const
{
    QVector<ScanRecord> results;
    if (!m_readDb)
        return results;

    // -- Load scan headers --
    const char* scanSql =
        "SELECT id, timestamp, total_scanned, suspicious_count, elapsed_seconds "
        "FROM scans ORDER BY id DESC;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_readDb, scanSql, -1, &stmt, nullptr) != SQLITE_OK) {
        qWarning() << "loadAllScanRecords: prepare failed:" << sqlite3_errmsg(m_readDb);
        return results;
    }

    // Map of scanId → index in results vector for fast finding insertion.
    QHash<qint64, int> idToIndex;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        qint64    id      = sqlite3_column_int64(stmt, 0);
        QString   tsStr   = QString::fromUtf8(
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
        int total   = sqlite3_column_int(stmt, 2);
        int susp    = sqlite3_column_int(stmt, 3);
        int elapsed = sqlite3_column_int(stmt, 4);

        ScanRecord r;
        r.timestamp       = QDateTime::fromString(tsStr, Qt::ISODate);
        r.totalScanned    = total;
        r.suspiciousCount = susp;
        r.elapsedSeconds  = elapsed;

        idToIndex[id] = results.size();
        results.append(r);
    }
    sqlite3_finalize(stmt);

    if (results.isEmpty())
        return results;

    // -- Load all findings in one pass --
    const char* findSql =
        "SELECT scan_id, file_path, file_name, file_size, last_modified, "
        "       sha256_hash, scan_status, reason, category, cve_id, cve_summary, cve_severity "
        "FROM scan_findings ORDER BY scan_id DESC, id ASC;";

    sqlite3_stmt* fstmt = nullptr;
    if (sqlite3_prepare_v2(m_readDb, findSql, -1, &fstmt, nullptr) != SQLITE_OK) {
        qWarning() << "loadAllScanRecords: prepare findings failed:" << sqlite3_errmsg(m_readDb);
        return results;   // return headers at least
    }

    while (sqlite3_step(fstmt) == SQLITE_ROW) {
        qint64 scanId = sqlite3_column_int64(fstmt, 0);
        if (!idToIndex.contains(scanId))
            continue;

        auto col = [&](int c) -> QString {
            const unsigned char* txt = sqlite3_column_text(fstmt, c);
            return txt ? QString::fromUtf8(reinterpret_cast<const char*>(txt)) : QString{};
        };

        SuspiciousFile sf;
        sf.filePath     = col(1);
        sf.fileName     = col(2);
        sf.sizeBytes    = sqlite3_column_int64(fstmt, 3);
        sf.lastModified = QDateTime::fromString(col(4), Qt::ISODate);
        // col(5) = sha256_hash  (stored but not in SuspiciousFile struct)
        // col(6) = scan_status
        sf.reason       = col(7);
        sf.category     = col(8);
        sf.cveId        = col(9);
        sf.cveSummary   = col(10);
        sf.cveSeverity  = col(11);

        results[idToIndex[scanId]].findings.append(sf);
    }
    sqlite3_finalize(fstmt);

    return results;
}

// ============================================================================
// loadRecentScanHeaders  (synchronous, UI thread – no findings loaded)
// ============================================================================
QVector<ScanRecord> ScanDatabase::loadRecentScanHeaders(int n) const
{
    QVector<ScanRecord> results;
    if (!m_readDb)
        return results;

    const char* sql =
        "SELECT timestamp, total_scanned, suspicious_count, elapsed_seconds "
        "FROM scans ORDER BY id DESC LIMIT ?;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_readDb, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        qWarning() << "loadRecentScanHeaders: prepare failed:" << sqlite3_errmsg(m_readDb);
        return results;
    }
    sqlite3_bind_int(stmt, 1, n);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        QString ts = QString::fromUtf8(
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));

        ScanRecord r;
        r.timestamp       = QDateTime::fromString(ts, Qt::ISODate);
        r.totalScanned    = sqlite3_column_int(stmt, 1);
        r.suspiciousCount = sqlite3_column_int(stmt, 2);
        r.elapsedSeconds  = sqlite3_column_int(stmt, 3);
        results.append(r);
    }
    sqlite3_finalize(stmt);
    return results;
}


// ============================================================================
// loadScanCache  (synchronous, UI thread)
// Returns path → CacheEntry for every row in scan_cache.
// Extended (v2): includes flagged-file metadata for result replay.
// Typical call time: <100ms even with 500k rows.
// ============================================================================
QHash<QString, CacheEntry> ScanDatabase::loadScanCache() const
{
    QHash<QString, CacheEntry> cache;
    if (!m_readDb)
        return cache;

    const char* sql =
        "SELECT file_path, last_modified, file_size, scan_result, "
        "       reason, category, classification_level, severity_level, "
        "       anomaly_score, ai_summary, key_indicators, recommended_actions, "
        "       ai_explanation, llm_available, "
        "       model_version, rules_version, config_hash "
        "FROM scan_cache;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_readDb, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        qWarning() << "loadScanCache: prepare failed:" << sqlite3_errmsg(m_readDb);
        return cache;
    }

    auto colText = [&](int c) -> QString {
        const unsigned char* txt = sqlite3_column_text(stmt, c);
        return txt ? QString::fromUtf8(reinterpret_cast<const char*>(txt)) : QString{};
    };

    // Phase 5 — current version triple. Cached after first call.
    const QString curModel  = CacheVersion::modelVersion();
    const QString curRules  = CacheVersion::rulesVersion();
    const QString curConfig = CacheVersion::configHash();

    int nClean = 0, nFlagged = 0, nStale = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CacheEntry e;
        e.filePath     = colText(0);
        e.lastModified = colText(1);
        // P5 perf: pre-compute epoch ms so the enumerator can integer-compare.
        e.lastModifiedMs = QDateTime::fromString(e.lastModified, Qt::ISODate)
                               .toMSecsSinceEpoch();
        e.fileSize     = sqlite3_column_int64(stmt, 2);
        e.isFlagged    = (colText(3) == QStringLiteral("flagged"));

        // Version filter: drop rows whose stored versions don't match the
        // current process-wide values. NULL columns (rows from before this
        // upgrade) never match a non-empty current value, which is safe:
        // those files get re-scanned. If the current values are themselves
        // empty (e.g. no model file present), we keep the row (avoids
        // wiping the cache on every dev-machine launch with no models).
        const QString rowModel  = colText(14);
        const QString rowRules  = colText(15);
        const QString rowConfig = colText(16);
        const bool versionsMatch =
              (curModel.isEmpty()  || rowModel  == curModel)
           && (curRules.isEmpty()  || rowRules  == curRules)
           && (curConfig.isEmpty() || rowConfig == curConfig);
        if (!versionsMatch) {
            ++nStale;
            continue;       // file gets re-scanned next time
        }

        if (e.isFlagged) {
            e.reason              = colText(4);
            e.category            = colText(5);
            e.classificationLevel = colText(6);
            e.severityLevel       = colText(7);
            e.anomalyScore        = static_cast<float>(sqlite3_column_double(stmt, 8));
            e.aiSummary           = colText(9);
            // key_indicators and recommended_actions stored as newline-delimited text
            QString ki = colText(10);
            if (!ki.isEmpty())
                e.keyIndicators = ki.split('\n', Qt::SkipEmptyParts);
            QString ra = colText(11);
            if (!ra.isEmpty())
                e.recommendedActions = ra.split('\n', Qt::SkipEmptyParts);
            e.aiExplanation  = colText(12);
            e.llmAvailable   = (sqlite3_column_int(stmt, 13) != 0);
            ++nFlagged;
        } else {
            ++nClean;
        }

        if (!e.filePath.isEmpty())
            cache.insert(e.filePath, e);
    }
    sqlite3_finalize(stmt);

    qDebug().noquote()
        << "loadScanCache: loaded" << cache.size() << "entries"
        << "(" << nClean << "clean," << nFlagged << "flagged)"
        << "| dropped" << nStale << "stale (model/rules/config changed)";
    return cache;
}

// ============================================================================
// flushScanCache  (async – writer thread)
// Upserts scan-result entries (both clean and flagged) from the scan.
// Uses INSERT OR REPLACE so re-scanned files update their timestamp.
// ============================================================================
void ScanDatabase::flushScanCache(const QVector<CacheEntry>& entries)
{
    if (entries.isEmpty())
        return;

    // Deep-copy so the lambda owns the data independently of the caller.
    QVector<CacheEntry> copy = entries;
    const QString now = QDateTime::currentDateTime().toString(Qt::ISODate);

    // Phase 5 — snapshot the version triple ONCE per flush. Computed on
    // the calling thread (UI thread on scan finish) so the writer thread
    // doesn't pay the cost; safe because CacheVersion is mutex-guarded
    // and these strings don't change during a scan.
    const QString modelV  = CacheVersion::modelVersion();
    const QString rulesV  = CacheVersion::rulesVersion();
    const QString configV = CacheVersion::configHash();

    enqueueWrite([copy, now, modelV, rulesV, configV](sqlite3* db) {
        const char* sql =
            "INSERT OR REPLACE INTO scan_cache "
            "(file_path, last_modified, last_scanned_at, file_size, scan_result, "
            " reason, category, classification_level, severity_level, "
            " anomaly_score, ai_summary, key_indicators, recommended_actions, "
            " ai_explanation, llm_available, "
            " model_version, rules_version, config_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

        execSql(db, "BEGIN;");
        int nClean = 0, nFlagged = 0;
        for (const CacheEntry& e : copy) {
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
                continue;
            bindText (stmt,  1, e.filePath);
            bindText (stmt,  2, e.lastModified);
            bindText (stmt,  3, now);
            bindInt64(stmt,  4, e.fileSize);
            bindText (stmt,  5, e.isFlagged ? QStringLiteral("flagged")
                                            : QStringLiteral("clean"));
            bindText (stmt,  6, e.reason);
            bindText (stmt,  7, e.category);
            bindText (stmt,  8, e.classificationLevel);
            bindText (stmt,  9, e.severityLevel);
            sqlite3_bind_double(stmt, 10, static_cast<double>(e.anomalyScore));
            bindText (stmt, 11, e.aiSummary);
            bindText (stmt, 12, e.keyIndicators.join('\n'));
            bindText (stmt, 13, e.recommendedActions.join('\n'));
            bindText (stmt, 14, e.aiExplanation);
            sqlite3_bind_int(stmt, 15, e.llmAvailable ? 1 : 0);
            // Phase 5 — version triple
            bindText (stmt, 16, modelV);
            bindText (stmt, 17, rulesV);
            bindText (stmt, 18, configV);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);

            if (e.isFlagged) ++nFlagged; else ++nClean;
        }
        execSql(db, "COMMIT;");
        qDebug() << "flushScanCache: upserted" << copy.size() << "entries"
                 << "(" << nClean << "clean," << nFlagged << "flagged)";
    });
}

// ============================================================================
// pruneStaleCache  (async – writer thread)
// Removes rows whose file no longer exists on disk.
// Cheap to call: SQLite DELETE is fast and the file-existence check is the
// only I/O.  Call after every N scans to keep the table from growing forever.
// ============================================================================
void ScanDatabase::pruneStaleCache()
{
    enqueueWrite([](sqlite3* db) {
        // Load all paths, check existence, delete the dead ones in one txn.
        const char* selSql = "SELECT file_path FROM scan_cache;";
        sqlite3_stmt* sel = nullptr;
        if (sqlite3_prepare_v2(db, selSql, -1, &sel, nullptr) != SQLITE_OK)
            return;

        QVector<QString> toDelete;
        while (sqlite3_step(sel) == SQLITE_ROW) {
            const unsigned char* p = sqlite3_column_text(sel, 0);
            if (!p) continue;
            QString path = QString::fromUtf8(reinterpret_cast<const char*>(p));
            if (!QFileInfo::exists(path))
                toDelete.append(path);
        }
        sqlite3_finalize(sel);

        if (toDelete.isEmpty())
            return;

        execSql(db, "BEGIN;");
        const char* delSql = "DELETE FROM scan_cache WHERE file_path = ?;";
        for (const QString& path : toDelete) {
            sqlite3_stmt* del = nullptr;
            if (sqlite3_prepare_v2(db, delSql, -1, &del, nullptr) != SQLITE_OK)
                continue;
            bindText(del, 1, path);
            sqlite3_step(del);
            sqlite3_finalize(del);
        }
        execSql(db, "COMMIT;");
        qDebug() << "pruneStaleCache: removed" << toDelete.size() << "stale entries";
    });
}

// ============================================================================
// loadLastScanRoot  (synchronous, UI thread)
// Returns the root path used in the most recently saved scan, or empty if none.
// ============================================================================
QString ScanDatabase::loadLastScanRoot() const
{
    if (!m_readDb)
        return {};

    const char* sql = "SELECT value FROM scan_state WHERE key = 'last_scan_root';";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_readDb, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return {};

    QString result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* val = sqlite3_column_text(stmt, 0);
        if (val)
            result = QString::fromUtf8(reinterpret_cast<const char*>(val));
    }
    sqlite3_finalize(stmt);
    return result;
}

// ============================================================================
// saveLastScanRoot  (async – writer thread)
// Upserts the 'last_scan_root' key so "Scan from Last Point" knows where to start.
// ============================================================================
void ScanDatabase::saveLastScanRoot(const QString& rootPath)
{
    if (rootPath.isEmpty())
        return;

    QString copy = rootPath;
    enqueueWrite([copy](sqlite3* db) {
        const char* sql =
            "INSERT OR REPLACE INTO scan_state (key, value) VALUES ('last_scan_root', ?);";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return;
        bindText(stmt, 1, copy);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    });
}

// ============================================================================
// WriterThread
// ============================================================================
ScanDatabase::WriterThread::WriterThread(const QString& dbPath, ScanDatabase* owner)
    : QThread(nullptr)
    , m_dbPath(dbPath)
    , m_owner(owner)
{}

void ScanDatabase::WriterThread::enqueue(DatabaseWriteTask task)
{
    QMutexLocker lock(&m_mutex);
    m_queue.enqueue(std::move(task));
    m_cond.wakeOne();
}

void ScanDatabase::WriterThread::requestStop()
{
    QMutexLocker lock(&m_mutex);
    m_stop = true;
    m_cond.wakeAll();
}

void ScanDatabase::WriterThread::run()
{
    sqlite3* db = nullptr;
    QByteArray pathUtf8 = m_dbPath.toUtf8();

    int rc = sqlite3_open_v2(
        pathUtf8.constData(),
        &db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        nullptr
    );

    if (rc != SQLITE_OK) {
        qWarning() << "WriterThread: could not open DB:" << sqlite3_errmsg(db);
        sqlite3_close(db);
        return;
    }

    // Apply pragmas on the write connection.
    execSql(db, kPragmas);

    // Ensure schema exists on this connection too (handles first-run race).
    execSql(db, kCreateScansTable);
    execSql(db, kCreateFindingsTable);
    execSql(db, kCreateCacheTable);
    // Suppress the expected "duplicate column" message on re-runs; warn
    // for any other migration error.
    for (int i = 0; kMigrateCacheColumns[i]; ++i) {
        QString migrateErr;
        if (!execSql(db, kMigrateCacheColumns[i], &migrateErr)
            && !migrateErr.contains("duplicate column", Qt::CaseInsensitive))
        {
            qWarning().noquote() << migrateErr;
        }
    }
    execSql(db, kCreateStateTable);

    qDebug() << "ScanDatabase WriterThread: started, db =" << m_dbPath;

    for (;;) {
        DatabaseWriteTask task;
        {
            QMutexLocker lock(&m_mutex);
            while (m_queue.isEmpty() && !m_stop)
                m_cond.wait(&m_mutex);

            if (m_stop && m_queue.isEmpty())
                break;

            task = m_queue.dequeue();
        }

        // Execute outside the lock so enqueue() doesn't stall.
        if (task)
            task(db);
    }

    sqlite3_close(db);
    qDebug() << "ScanDatabase WriterThread: stopped.";
}

bool ScanDatabase::clearAllData()
{
    if (m_dbPath.isEmpty()) return false;

    sqlite3* db;
    // Open connection solely for the wipe operation
    if (sqlite3_open_v2(m_dbPath.toUtf8().constData(), &db, SQLITE_OPEN_READWRITE, nullptr) != SQLITE_OK) {
        qWarning() << "Failed to open DB for clearing:" << sqlite3_errmsg(db);
        return false;
    }

    // Safely clear the data while maintaining schema
    const char* queries[] = {
        "DELETE FROM scans;",
        "DELETE FROM scan_findings;",
        "DELETE FROM scan_cache;",
        "DELETE FROM scan_state;",
        "VACUUM;"
    };

    bool success = true;
    for (const char* query : queries) {
        char* errMsg = nullptr;
        if (sqlite3_exec(db, query, nullptr, nullptr, &errMsg) != SQLITE_OK) {
            qWarning() << "Clear cache query failed:" << errMsg;
            sqlite3_free(errMsg);
            success = false;
        }
    }

    sqlite3_close(db);
    return success;
}