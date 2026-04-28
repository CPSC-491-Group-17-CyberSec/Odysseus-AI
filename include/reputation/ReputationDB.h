#pragma once
// ============================================================================
// ReputationDB.h  –  Phase 1: structured local reputation database
//
// Replaces the flat-text data/malware_hashes.txt lookup with a real SQLite
// table that captures the kind of context an analyst actually needs:
//
//   • family        – e.g. "WannaCry", "Emotet"
//   • source        – where the IOC came from (VirusTotal, MalwareBazaar,
//                     internal triage, user-added, ...)
//   • severity      – low / medium / high / critical
//   • first_seen    – when this hash first entered the DB
//   • last_seen     – most recent time we re-confirmed / re-encountered it
//   • prevalence    – how many times we've seen this hash on this machine
//                     (useful proxy for "is this a widely-deployed sample")
//   • signing_status– cached result of code-signing check (-1/0/1/2)
//   • signer_id     – Authority/Team-ID/SubjectCN of the signer (if signed)
//   • notes         – free-text analyst notes
//
// Bootstrap:
//   On first run, ReputationDB::open() seeds the table from the existing
//   data/malware_hashes.txt file (so we don't lose the curated list). The
//   migration is idempotent: re-running just inserts new rows for unseen
//   hashes.
//
// Threading:
//   • All read methods are safe to call from any thread (each maintains its
//     own connection or uses a serialized read connection).
//   • Writes are serialized through a small internal mutex. Volume is low
//     (every flagged file = one row update) so we don't need a writer
//     thread like ScanDatabase has.
// ============================================================================

#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QHash>
#include <QMutex>

struct sqlite3;

// ---------------------------------------------------------------------------
// Reputation severity (mirrors SuspiciousFile severity but is the analyst's
// view, not the ML model's view).
// ---------------------------------------------------------------------------
enum class ReputationSeverity {
    Unknown  = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
};

QString severityToText(ReputationSeverity s);
ReputationSeverity severityFromText(const QString& s);

// ---------------------------------------------------------------------------
// ReputationRecord  –  one row in the reputation table
// ---------------------------------------------------------------------------
struct ReputationRecord
{
    QString             sha256;
    QString             family;
    QString             source;
    ReputationSeverity  severity      = ReputationSeverity::Unknown;
    QDateTime           firstSeen;
    QDateTime           lastSeen;
    int                 prevalence    = 0;
    int                 signingStatus = -1;   // -1=unknown, 0=unsigned,
                                              //  1=signed-untrusted, 2=signed-trusted
    QString             signerId;
    QString             notes;

    bool isKnown() const { return !sha256.isEmpty(); }
};

// ---------------------------------------------------------------------------
// ReputationDB
// ---------------------------------------------------------------------------
class ReputationDB
{
public:
    ReputationDB();
    ~ReputationDB();

    /// Open or create the SQLite database alongside the application data
    /// directory. Seeds from data/malware_hashes.txt on first run.
    /// Returns true on success.
    bool open(const QString& appDataDir, const QString& seedHashFile);

    /// Close the database (also called by destructor).
    void close();

    bool isOpen() const { return m_db != nullptr; }

    /// Path of the SQLite database file (for diagnostics).
    QString path() const { return m_dbPath; }

    // -----------------------------------------------------------------------
    // Lookups  (read-only)
    // -----------------------------------------------------------------------

    /// Look up a hash. Returns a populated ReputationRecord, or one with
    /// empty sha256 if not known.
    ReputationRecord lookup(const QString& sha256) const;

    /// True if the given SHA-256 is in the database.
    bool contains(const QString& sha256) const;

    /// Number of rows.
    int rowCount() const;

    // -----------------------------------------------------------------------
    // In-memory hot cache  (built once at startup for fast scanner lookup)
    // -----------------------------------------------------------------------

    /// Snapshot the entire reputation table into a QHash<sha256, family> for
    /// the scan workers to use without opening a DB connection per file.
    /// Cheap (typical DB sizes < 100k rows). Re-snapshot after large imports.
    QHash<QString, QString> snapshotHashIndex() const;

    /// Snapshot the full record map (used when the scanner wants metadata
    /// beyond just the family name).
    QHash<QString, ReputationRecord> snapshotFullRecords() const;

    // -----------------------------------------------------------------------
    // Mutations  (writes)
    // -----------------------------------------------------------------------

    /// Insert or update a reputation record. If the row already exists, the
    /// non-empty fields of `r` overwrite, prevalence is incremented, and
    /// last_seen is bumped to now.
    bool upsert(const ReputationRecord& r);

    /// Bump prevalence + last_seen for an existing hash (no-op if missing).
    /// Useful as a side-effect of a hash hit during scan.
    bool recordSighting(const QString& sha256);

    /// Bulk-import from a plain-text hash file in the format used by
    /// data/malware_hashes.txt:  "<sha256>  <family / description>"
    /// Returns the number of new rows inserted.
    int importFromTextFile(const QString& path, const QString& source);

private:
    bool createSchema();
    bool seedFromBlocklist(const QString& path);

    sqlite3*      m_db = nullptr;
    QString       m_dbPath;
    mutable QMutex m_mutex;     // serializes writes; reads also locked since
                                // we're using a single connection
};
