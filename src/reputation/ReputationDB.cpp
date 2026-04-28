// ============================================================================
// ReputationDB.cpp  –  structured local reputation database (Phase 1)
//
// Schema:
//   reputation(
//       sha256          TEXT PRIMARY KEY,
//       family          TEXT,
//       source          TEXT,
//       severity        INTEGER,        -- ReputationSeverity enum value
//       first_seen      TEXT,           -- ISO-8601
//       last_seen       TEXT,           -- ISO-8601
//       prevalence      INTEGER DEFAULT 0,
//       signing_status  INTEGER DEFAULT -1,
//       signer_id       TEXT,
//       notes           TEXT
//   )
//
// We deliberately use the bundled SQLite amalgamation already in the project
// (src/db/sqlite3.c) rather than QtSql, so this module has zero new
// dependencies. The header lives in src/db/sqlite3.h.
// ============================================================================

#include "reputation/ReputationDB.h"

#include "../db/sqlite3.h"   // bundled amalgamation header

#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QDateTime>
#include <QDebug>
#include <QMutexLocker>
#include <QTextStream>

// ============================================================================
// Severity text mapping
// ============================================================================
QString severityToText(ReputationSeverity s)
{
    switch (s) {
        case ReputationSeverity::Critical: return "critical";
        case ReputationSeverity::High:     return "high";
        case ReputationSeverity::Medium:   return "medium";
        case ReputationSeverity::Low:      return "low";
        default:                            return "unknown";
    }
}

ReputationSeverity severityFromText(const QString& s)
{
    const QString t = s.trimmed().toLower();
    if (t == "critical") return ReputationSeverity::Critical;
    if (t == "high")     return ReputationSeverity::High;
    if (t == "medium")   return ReputationSeverity::Medium;
    if (t == "low")      return ReputationSeverity::Low;
    return ReputationSeverity::Unknown;
}

// ============================================================================
// Lifecycle
// ============================================================================
ReputationDB::ReputationDB() = default;

ReputationDB::~ReputationDB() { close(); }

bool ReputationDB::open(const QString& appDataDir, const QString& seedHashFile)
{
    QMutexLocker lock(&m_mutex);

    QDir().mkpath(appDataDir);                        // ensure dir exists
    m_dbPath = QDir(appDataDir).absoluteFilePath("odysseus_reputation.db");

    if (sqlite3_open(m_dbPath.toUtf8().constData(), &m_db) != SQLITE_OK) {
        qWarning() << "[Reputation] sqlite3_open failed:" << sqlite3_errmsg(m_db);
        if (m_db) sqlite3_close(m_db);
        m_db = nullptr;
        return false;
    }

    // Pragmas for a small write-light read-heavy DB.
    sqlite3_exec(m_db, "PRAGMA journal_mode = WAL;",       nullptr, nullptr, nullptr);
    sqlite3_exec(m_db, "PRAGMA synchronous  = NORMAL;",    nullptr, nullptr, nullptr);
    sqlite3_exec(m_db, "PRAGMA temp_store   = MEMORY;",    nullptr, nullptr, nullptr);

    if (!createSchema()) {
        sqlite3_close(m_db);
        m_db = nullptr;
        return false;
    }

    // Drop the lock briefly so seedFromBlocklist (which calls upsert, which
    // locks) doesn't deadlock.
    lock.unlock();

    if (seedHashFile.isEmpty()) {
        qInfo() << "[Reputation] no seed file provided — skipping seeding";
    } else if (!QFile::exists(seedHashFile)) {
        qWarning().noquote()
            << "[Reputation] seed file does not exist:" << seedHashFile
            << "— DB will start empty (will populate as scans flag samples)";
    } else if (rowCount() > 0) {
        // Already populated — never re-import (preserves user-curated rows).
        qInfo().noquote()
            << QString("[Reputation] DB already populated (%1 rows) — "
                       "seed file %2 ignored").arg(rowCount()).arg(seedHashFile);
    } else {
        const int n = importFromTextFile(seedHashFile, "seed/malware_hashes.txt");
        if (n > 0) {
            qInfo().noquote()
                << QString("[Reputation] seeded %1 row(s) from %2").arg(n).arg(seedHashFile);
        } else {
            qWarning().noquote()
                << "[Reputation] seed file" << seedHashFile
                << "produced 0 rows — file may be empty or all hashes are malformed";
        }
    }

    return true;
}

void ReputationDB::close()
{
    QMutexLocker lock(&m_mutex);
    if (m_db) {
        sqlite3_close(m_db);
        m_db = nullptr;
    }
}

bool ReputationDB::createSchema()
{
    // Note: caller already holds m_mutex.
    constexpr const char* kSchema =
        "CREATE TABLE IF NOT EXISTS reputation ("
        "  sha256          TEXT PRIMARY KEY,"
        "  family          TEXT,"
        "  source          TEXT,"
        "  severity        INTEGER DEFAULT 0,"
        "  first_seen      TEXT,"
        "  last_seen       TEXT,"
        "  prevalence      INTEGER DEFAULT 0,"
        "  signing_status  INTEGER DEFAULT -1,"
        "  signer_id       TEXT,"
        "  notes           TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_rep_family   ON reputation(family);"
        "CREATE INDEX IF NOT EXISTS idx_rep_severity ON reputation(severity);";

    char* err = nullptr;
    if (sqlite3_exec(m_db, kSchema, nullptr, nullptr, &err) != SQLITE_OK) {
        qWarning() << "[Reputation] schema create failed:" << (err ? err : "?");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

// ============================================================================
// Lookups
// ============================================================================
ReputationRecord ReputationDB::lookup(const QString& sha256) const
{
    ReputationRecord r;
    if (!m_db) return r;

    QMutexLocker lock(&m_mutex);

    constexpr const char* kSql =
        "SELECT sha256, family, source, severity, first_seen, last_seen, "
        "       prevalence, signing_status, signer_id, notes "
        "FROM reputation WHERE sha256 = ?;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, kSql, -1, &stmt, nullptr) != SQLITE_OK) return r;

    const QByteArray hashLower = sha256.toLower().toUtf8();
    sqlite3_bind_text(stmt, 1, hashLower.constData(), hashLower.size(), SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        auto col = [&](int i) -> QString {
            const unsigned char* t = sqlite3_column_text(stmt, i);
            return t ? QString::fromUtf8(reinterpret_cast<const char*>(t)) : QString();
        };
        r.sha256        = col(0);
        r.family        = col(1);
        r.source        = col(2);
        r.severity      = static_cast<ReputationSeverity>(sqlite3_column_int(stmt, 3));
        r.firstSeen     = QDateTime::fromString(col(4), Qt::ISODate);
        r.lastSeen      = QDateTime::fromString(col(5), Qt::ISODate);
        r.prevalence    = sqlite3_column_int(stmt, 6);
        r.signingStatus = sqlite3_column_int(stmt, 7);
        r.signerId      = col(8);
        r.notes         = col(9);
    }
    sqlite3_finalize(stmt);
    return r;
}

bool ReputationDB::contains(const QString& sha256) const
{
    return !lookup(sha256).sha256.isEmpty();
}

int ReputationDB::rowCount() const
{
    if (!m_db) return 0;
    QMutexLocker lock(&m_mutex);

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, "SELECT COUNT(*) FROM reputation;", -1,
                           &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    int n = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        n = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

// ============================================================================
// Snapshots (used by the scanner workers as a lock-free hot cache)
// ============================================================================
QHash<QString, QString> ReputationDB::snapshotHashIndex() const
{
    QHash<QString, QString> out;
    if (!m_db) return out;
    QMutexLocker lock(&m_mutex);

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, "SELECT sha256, family FROM reputation;", -1,
                           &stmt, nullptr) != SQLITE_OK) return out;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* h = sqlite3_column_text(stmt, 0);
        const unsigned char* f = sqlite3_column_text(stmt, 1);
        if (!h) continue;
        out.insert(QString::fromUtf8(reinterpret_cast<const char*>(h)),
                   f ? QString::fromUtf8(reinterpret_cast<const char*>(f))
                     : QStringLiteral("Unknown"));
    }
    sqlite3_finalize(stmt);
    return out;
}

QHash<QString, ReputationRecord> ReputationDB::snapshotFullRecords() const
{
    QHash<QString, ReputationRecord> out;
    if (!m_db) return out;
    QMutexLocker lock(&m_mutex);

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db,
            "SELECT sha256, family, source, severity, first_seen, last_seen, "
            "       prevalence, signing_status, signer_id, notes "
            "FROM reputation;", -1, &stmt, nullptr) != SQLITE_OK) return out;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto col = [&](int i) -> QString {
            const unsigned char* t = sqlite3_column_text(stmt, i);
            return t ? QString::fromUtf8(reinterpret_cast<const char*>(t)) : QString();
        };
        ReputationRecord r;
        r.sha256        = col(0);
        r.family        = col(1);
        r.source        = col(2);
        r.severity      = static_cast<ReputationSeverity>(sqlite3_column_int(stmt, 3));
        r.firstSeen     = QDateTime::fromString(col(4), Qt::ISODate);
        r.lastSeen      = QDateTime::fromString(col(5), Qt::ISODate);
        r.prevalence    = sqlite3_column_int(stmt, 6);
        r.signingStatus = sqlite3_column_int(stmt, 7);
        r.signerId      = col(8);
        r.notes         = col(9);
        out.insert(r.sha256, r);
    }
    sqlite3_finalize(stmt);
    return out;
}

// ============================================================================
// Mutations
// ============================================================================
bool ReputationDB::upsert(const ReputationRecord& r)
{
    if (!m_db || r.sha256.isEmpty()) return false;
    QMutexLocker lock(&m_mutex);

    // ON CONFLICT update path bumps prevalence + last_seen and overwrites any
    // non-empty incoming field with COALESCE.
    constexpr const char* kSql =
        "INSERT INTO reputation "
        "(sha256, family, source, severity, first_seen, last_seen, prevalence, "
        " signing_status, signer_id, notes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(sha256) DO UPDATE SET "
        "  family         = COALESCE(NULLIF(excluded.family, ''),         family),"
        "  source         = COALESCE(NULLIF(excluded.source, ''),         source),"
        "  severity       = MAX(severity, excluded.severity),"
        "  last_seen      = excluded.last_seen,"
        "  prevalence     = prevalence + 1,"
        "  signing_status = CASE WHEN excluded.signing_status >= 0 "
        "                        THEN excluded.signing_status ELSE signing_status END,"
        "  signer_id      = COALESCE(NULLIF(excluded.signer_id, ''),      signer_id),"
        "  notes          = COALESCE(NULLIF(excluded.notes, ''),          notes);";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, kSql, -1, &stmt, nullptr) != SQLITE_OK) {
        qWarning() << "[Reputation] upsert prepare failed:" << sqlite3_errmsg(m_db);
        return false;
    }

    const QString nowIso  = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
    const QString firstIso = r.firstSeen.isValid()
                              ? r.firstSeen.toString(Qt::ISODate) : nowIso;
    const QString lastIso  = r.lastSeen.isValid()
                              ? r.lastSeen.toString(Qt::ISODate)  : nowIso;

    auto bindText = [&](int i, const QString& s) {
        const QByteArray b = s.toUtf8();
        sqlite3_bind_text(stmt, i, b.constData(), b.size(), SQLITE_TRANSIENT);
    };

    bindText(1, r.sha256.toLower());
    bindText(2, r.family);
    bindText(3, r.source);
    sqlite3_bind_int (stmt, 4, static_cast<int>(r.severity));
    bindText(5, firstIso);
    bindText(6, lastIso);
    sqlite3_bind_int (stmt, 7, std::max(1, r.prevalence));
    sqlite3_bind_int (stmt, 8, r.signingStatus);
    bindText(9, r.signerId);
    bindText(10, r.notes);

    const bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    if (!ok)
        qWarning() << "[Reputation] upsert failed:" << sqlite3_errmsg(m_db);
    return ok;
}

bool ReputationDB::recordSighting(const QString& sha256)
{
    if (!m_db || sha256.isEmpty()) return false;
    QMutexLocker lock(&m_mutex);

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db,
            "UPDATE reputation SET prevalence = prevalence + 1, last_seen = ? "
            "WHERE sha256 = ?;", -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    const QByteArray nowIso = QDateTime::currentDateTimeUtc()
                                  .toString(Qt::ISODate).toUtf8();
    const QByteArray hashLower = sha256.toLower().toUtf8();
    sqlite3_bind_text(stmt, 1, nowIso.constData(),    nowIso.size(),    SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, hashLower.constData(), hashLower.size(), SQLITE_TRANSIENT);
    const bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

// ============================================================================
// Bulk import from the existing flat-text blocklist
// ============================================================================
int ReputationDB::importFromTextFile(const QString& path, const QString& source)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning() << "[Reputation] import: cannot open" << path;
        return 0;
    }

    int inserted   = 0;
    int skippedBad = 0;
    int upsertFail = 0;
    sqlite3_exec(m_db, "BEGIN;", nullptr, nullptr, nullptr);

    QTextStream in(&f);
    while (!in.atEnd()) {
        const QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith('#')) continue;

        const int sp = line.indexOf(' ');
        const QString hash = (sp > 0 ? line.left(sp) : line).toLower();
        if (hash.length() != 64) {                // SHA-256 = 64 hex chars
            ++skippedBad;
            continue;
        }

        const QString family = (sp > 0)
            ? line.mid(sp + 1).trimmed()
            : QStringLiteral("Unknown");

        ReputationRecord r;
        r.sha256   = hash;
        r.family   = family;
        r.source   = source;
        r.severity = ReputationSeverity::High;     // blocklist entries are HIGH by default
        r.firstSeen = QDateTime::currentDateTimeUtc();
        r.lastSeen  = r.firstSeen;
        r.prevalence = 0;                          // not yet seen on this host
        if (upsert(r)) ++inserted;
        else           ++upsertFail;
    }

    sqlite3_exec(m_db, "COMMIT;", nullptr, nullptr, nullptr);

    if (skippedBad > 0)
        qWarning().noquote()
            << QString("[Reputation] import: skipped %1 malformed line(s) "
                       "(non-64-char hash field)").arg(skippedBad);
    if (upsertFail > 0)
        qWarning().noquote()
            << QString("[Reputation] import: %1 row(s) failed to upsert "
                       "— last sqlite error: %2")
                .arg(upsertFail).arg(sqlite3_errmsg(m_db));
    return inserted;
}
