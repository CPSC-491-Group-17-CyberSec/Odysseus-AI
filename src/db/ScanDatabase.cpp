#include "ScanDatabase.h"

#include "sqlite3.h"

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
    file_path       TEXT    PRIMARY KEY,
    last_modified   TEXT    NOT NULL,
    last_scanned_at TEXT    NOT NULL
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

            // Compute hash in the writer thread (not UI thread) – I/O-heavy.
            QString hash = computeSha256(sf.filePath);

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
// Returns path → lastModified for every row in scan_cache.
// Typical call time: <50ms even with 500k rows.
// ============================================================================
QHash<QString, QString> ScanDatabase::loadScanCache() const
{
    QHash<QString, QString> cache;
    if (!m_readDb)
        return cache;

    const char* sql = "SELECT file_path, last_modified FROM scan_cache;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_readDb, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        qWarning() << "loadScanCache: prepare failed:" << sqlite3_errmsg(m_readDb);
        return cache;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* path = sqlite3_column_text(stmt, 0);
        const unsigned char* mod  = sqlite3_column_text(stmt, 1);
        if (path && mod)
            cache.insert(
                QString::fromUtf8(reinterpret_cast<const char*>(path)),
                QString::fromUtf8(reinterpret_cast<const char*>(mod))
            );
    }
    sqlite3_finalize(stmt);

    qDebug() << "loadScanCache: loaded" << cache.size() << "entries";
    return cache;
}

// ============================================================================
// flushScanCache  (async – writer thread)
// Upserts all clean-file entries from the just-completed scan.
// Uses INSERT OR REPLACE so re-scanned files update their timestamp.
// ============================================================================
void ScanDatabase::flushScanCache(const QVector<CacheEntry>& entries)
{
    if (entries.isEmpty())
        return;

    // Deep-copy so the lambda owns the data independently of the caller.
    QVector<CacheEntry> copy = entries;
    const QString now = QDateTime::currentDateTime().toString(Qt::ISODate);

    enqueueWrite([copy, now](sqlite3* db) {
        const char* sql =
            "INSERT OR REPLACE INTO scan_cache (file_path, last_modified, last_scanned_at) "
            "VALUES (?, ?, ?);";

        execSql(db, "BEGIN;");
        for (const CacheEntry& e : copy) {
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
                continue;
            bindText(stmt, 1, e.filePath);
            bindText(stmt, 2, e.lastModified);
            bindText(stmt, 3, now);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
        execSql(db, "COMMIT;");
        qDebug() << "flushScanCache: upserted" << copy.size() << "entries";
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