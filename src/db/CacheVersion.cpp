// ============================================================================
// CacheVersion.cpp  –  computes the three cache-keying strings.
// ============================================================================

#include "db/CacheVersion.h"

#include "core/ScannerConfig.h"

#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QDirIterator>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QMutex>
#include <QMutexLocker>
#include <QDebug>

namespace CacheVersion {

namespace {

QMutex   g_mutex;
QString  g_modelVersion;
QString  g_rulesVersion;
QString  g_configHash;
bool     g_modelComputed  = false;
bool     g_rulesComputed  = false;
// Config hash is cheap; we recompute it every call so toggle changes
// during the session take effect on the next scan without restart.

QStringList searchRoots(const QString& sub)
{
    const QString appDir = QCoreApplication::applicationDirPath();
    return {
        appDir + "/" + sub,
        appDir + "/../" + sub,
        appDir + "/../../" + sub,
        appDir + "/../../../" + sub,
    };
}

QString findFirstExisting(const QStringList& candidates)
{
    for (const QString& p : candidates)
        if (QFileInfo::exists(p)) return p;
    return {};
}

QString shortHashFile(const QString& path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};
    QCryptographicHash h(QCryptographicHash::Sha256);
    char buf[64 * 1024];
    while (!f.atEnd()) {
        const qint64 n = f.read(buf, sizeof(buf));
        if (n <= 0) break;
        h.addData(QByteArrayView(buf, static_cast<qsizetype>(n)));
    }
    f.close();
    return QString::fromLatin1(h.result().toHex().left(16));   // short-form
}

QString computeModelVersion()
{
    // Hash the model files we know about. Order is deterministic.
    static const QStringList kModelFiles = {
        "data/anomaly_model.onnx",
        "data/anomaly_model_v2.onnx",
        "data/anomaly_model_v3.onnx",
        "data/anomaly_model_v4_ember.onnx",
        "data/ember_lgbm_model.txt",
        "data/ember_scaler.bin",
    };

    QCryptographicHash combined(QCryptographicHash::Sha256);
    int found = 0;
    for (const QString& sub : kModelFiles) {
        const QString p = findFirstExisting(searchRoots(sub));
        if (p.isEmpty()) continue;
        const QString h = shortHashFile(p);
        if (h.isEmpty()) continue;
        combined.addData(sub.toUtf8());
        combined.addData(":", 1);
        combined.addData(h.toUtf8());
        combined.addData("\n", 1);
        ++found;
    }
    if (found == 0) return {};
    return QString::fromLatin1(combined.result().toHex().left(16));
}

QString computeRulesVersion()
{
    const QString rulesDir = findFirstExisting(searchRoots("data/yara_rules"));
    if (rulesDir.isEmpty()) return {};

    QDirIterator it(rulesDir,
                    { "*.yar", "*.yara" },
                    QDir::Files,
                    QDirIterator::Subdirectories);
    int count = 0;
    QDateTime latest;
    while (it.hasNext()) {
        it.next();
        const QFileInfo fi = it.fileInfo();
        const QDateTime mt = fi.lastModified();
        if (!latest.isValid() || mt > latest) latest = mt;
        ++count;
    }
    if (count == 0) return {};
    return QString("%1:%2")
               .arg(count)
               .arg(latest.toString(Qt::ISODate));
}

QString computeConfigHash()
{
    const ScannerConfig& cfg = ScannerConfigStore::current();
    const QByteArray bytes = QJsonDocument(cfg.toJson())
                                 .toJson(QJsonDocument::Compact);
    return QString::fromLatin1(
        QCryptographicHash::hash(bytes, QCryptographicHash::Sha256)
            .toHex()
            .left(16));
}

}  // anonymous

QString modelVersion()
{
    QMutexLocker lock(&g_mutex);
    if (!g_modelComputed) {
        g_modelVersion = computeModelVersion();
        g_modelComputed = true;
        qInfo().noquote() << "[CacheVersion] model =" << g_modelVersion;
    }
    return g_modelVersion;
}

QString rulesVersion()
{
    QMutexLocker lock(&g_mutex);
    if (!g_rulesComputed) {
        g_rulesVersion = computeRulesVersion();
        g_rulesComputed = true;
        qInfo().noquote() << "[CacheVersion] rules =" << g_rulesVersion;
    }
    return g_rulesVersion;
}

QString configHash()
{
    QMutexLocker lock(&g_mutex);
    g_configHash = computeConfigHash();
    return g_configHash;
}

void invalidate()
{
    QMutexLocker lock(&g_mutex);
    g_modelComputed = false;
    g_rulesComputed = false;
    g_modelVersion.clear();
    g_rulesVersion.clear();
}

}  // namespace CacheVersion
