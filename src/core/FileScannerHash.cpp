// FileScannerHash.cpp
// SHA-256 hash database loading and hash-based malware detection.
// Compiled with -O3: this is the most CPU/IO-intensive path in the scanner.

#include "FileScanner.h"

#include <QFile>
#include <QCryptographicHash>
#include <QCoreApplication>

// ============================================================================
// loadHashDatabase  –  static, called once at worker construction.
// Searches candidate paths relative to the executable so the file is found
// both during development (build dir) and after install.
// ============================================================================
QHash<QString, QString> FileScannerWorker::loadHashDatabase()
{
    QHash<QString, QString> db;

    const QString appDir = QCoreApplication::applicationDirPath();
    const QStringList candidates = {
        appDir + "/data/malware_hashes.txt",         // installed / cmake-copied
        appDir + "/../data/malware_hashes.txt",       // one level up
        appDir + "/../../data/malware_hashes.txt",    // two levels up (source root)
        appDir + "/../../../data/malware_hashes.txt", // three levels (nested build)
    };

    for (const QString& path : candidates) {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
            continue;

        while (!f.atEnd()) {
            const QString line = QString::fromUtf8(f.readLine()).trimmed();
            if (line.isEmpty() || line.startsWith('#'))
                continue;

            // Format: <sha256_hex>  <Malware Name / Description>
            const int spaceIdx = line.indexOf(' ');
            const QString hash = (spaceIdx > 0 ? line.left(spaceIdx) : line).toLower();
            const QString name = (spaceIdx > 0) ? line.mid(spaceIdx + 1).trimmed()
                                                 : QStringLiteral("Unknown Malware");

            if (hash.length() == 64)  // SHA-256 = 64 hex chars
                db.insert(hash, name);
        }
        break;  // loaded from first valid path
    }

    return db;
}

// ============================================================================
// checkByHash  –  SHA-256 the file, look it up in the loaded hash database.
//
// Skips:
//   - extensions in m_noHashExtensions (system artefacts / media)
//   - network filesystems (high-latency I/O)
//   - files larger than 200 MB (no real malware sample exceeds this)
//   - empty hash DB (database file not found)
//
// Reads in 64 KB chunks to avoid loading the entire file into memory.
// ============================================================================
bool FileScannerWorker::checkByHash(const QString& filePath,
                                     const QString& ext,
                                     qint64         fileSize,
                                     QString&       outReason,
                                     QString&       outCategory) const
{
    if (m_noHashExtensions.contains(ext))
        return false;

    if (m_ctx.isNetworkFs)
        return false;

    constexpr qint64 maxHashBytes = 200LL * 1024 * 1024;
    if (fileSize <= 0 || fileSize > maxHashBytes)
        return false;

    if (m_hashDb.isEmpty())
        return false;

    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly))
        return false;

    QCryptographicHash hasher(QCryptographicHash::Sha256);
    char buf[65536];
    while (!f.atEnd()) {
        const qint64 n = f.read(buf, sizeof(buf));
        if (n <= 0) break;
        hasher.addData(QByteArrayView(buf, static_cast<qsizetype>(n)));
    }
    f.close();

    const QString hex = QString::fromLatin1(hasher.result().toHex()).toLower();

    const auto it = m_hashDb.constFind(hex);
    if (it != m_hashDb.constEnd()) {
        outCategory = "Known Malware Hash";
        outReason   = QString("SHA-256 matches known malware sample: %1  [%2]")
                          .arg(it.value(), hex);
        return true;
    }

    return false;
}
