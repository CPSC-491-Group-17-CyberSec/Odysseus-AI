// ============================================================================
// ScannerConfig.cpp  –  JSON-backed singleton for per-feature toggles
//
// File format (odysseus_config.json):
//
// {
//   "yaraEnabled":          true,
//   "reputationAutoUpsert": true,
//   "codeSigningEnabled":   true,
//   "verboseLogging":       false,
//   "experimentalRules":    false,
//   "experimentalSubdir":   "experimental",
//   "maxCompileErrors":     100
// }
//
// Robustness rules:
//   • Missing fields fall back to defaults (no parse error).
//   • Wrong types (e.g. yaraEnabled = "yes") fall back to defaults too,
//     not errors — we never want a bad config to crash startup.
//   • The file is created on first load if it doesn't exist, so users can
//     find a template by simply running the app once and then opening it.
// ============================================================================

#include "core/ScannerConfig.h"

#include <QDebug>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutex>
#include <QMutexLocker>
#include <QStandardPaths>

// ============================================================================
// JSON helpers (defensive — never throw on bad input)
// ============================================================================
namespace {

bool jsonBool(const QJsonObject& o, const QString& key, bool fallback) {
  if (!o.contains(key))
    return fallback;
  const auto v = o.value(key);
  return v.isBool() ? v.toBool() : fallback;
}
int jsonInt(const QJsonObject& o, const QString& key, int fallback) {
  if (!o.contains(key))
    return fallback;
  const auto v = o.value(key);
  if (v.isDouble())
    return static_cast<int>(v.toDouble());
  return fallback;
}
QString jsonStr(const QJsonObject& o, const QString& key, const QString& fallback) {
  if (!o.contains(key))
    return fallback;
  const auto v = o.value(key);
  return v.isString() ? v.toString() : fallback;
}

}  // namespace

// ============================================================================
// ScannerConfig  –  serialization
// ============================================================================
QJsonObject ScannerConfig::toJson() const {
  QJsonObject o;
  o["yaraEnabled"] = yaraEnabled;
  o["reputationAutoUpsert"] = reputationAutoUpsert;
  o["codeSigningEnabled"] = codeSigningEnabled;
  o["verboseLogging"] = verboseLogging;
  o["experimentalRules"] = experimentalRules;
  o["experimentalSubdir"] = experimentalSubdir;
  o["maxCompileErrors"] = maxCompileErrors;
  // Phase 2
  o["systemMonitoringEnabled"] = systemMonitoringEnabled;
  o["processScanEnabled"] = processScanEnabled;
  o["persistenceScanEnabled"] = persistenceScanEnabled;
  o["suspiciousProcessHeuristicsEnabled"] = suspiciousProcessHeuristicsEnabled;
  // Phase 3
  o["rootkitAwarenessEnabled"] = rootkitAwarenessEnabled;
  o["processCrossViewCheckEnabled"] = processCrossViewCheckEnabled;
  o["kernelExtensionCheckEnabled"] = kernelExtensionCheckEnabled;
  o["integrityCheckEnabled"] = integrityCheckEnabled;
  // Phase 4 (EDR-Lite)
  o["edrLiteEnabled"] = edrLiteEnabled;
  o["monitoringIntervalSeconds"] = monitoringIntervalSeconds;
  o["alertOnNewProcess"] = alertOnNewProcess;
  o["alertOnNewPersistence"] = alertOnNewPersistence;
  o["alertOnIntegrityMismatch"] = alertOnIntegrityMismatch;
  o["alertOnKernelExtensionChange"] = alertOnKernelExtensionChange;
  return o;
}

ScannerConfig ScannerConfig::fromJson(const QJsonObject& o) {
  ScannerConfig defaults;
  ScannerConfig c;
  c.yaraEnabled = jsonBool(o, "yaraEnabled", defaults.yaraEnabled);
  c.reputationAutoUpsert = jsonBool(o, "reputationAutoUpsert", defaults.reputationAutoUpsert);
  c.codeSigningEnabled = jsonBool(o, "codeSigningEnabled", defaults.codeSigningEnabled);
  c.verboseLogging = jsonBool(o, "verboseLogging", defaults.verboseLogging);
  c.experimentalRules = jsonBool(o, "experimentalRules", defaults.experimentalRules);
  c.experimentalSubdir = jsonStr(o, "experimentalSubdir", defaults.experimentalSubdir);
  c.maxCompileErrors = jsonInt(o, "maxCompileErrors", defaults.maxCompileErrors);
  // Phase 2
  c.systemMonitoringEnabled =
      jsonBool(o, "systemMonitoringEnabled", defaults.systemMonitoringEnabled);
  c.processScanEnabled = jsonBool(o, "processScanEnabled", defaults.processScanEnabled);
  c.persistenceScanEnabled = jsonBool(o, "persistenceScanEnabled", defaults.persistenceScanEnabled);
  c.suspiciousProcessHeuristicsEnabled = jsonBool(
      o, "suspiciousProcessHeuristicsEnabled", defaults.suspiciousProcessHeuristicsEnabled);
  // Phase 3
  c.rootkitAwarenessEnabled =
      jsonBool(o, "rootkitAwarenessEnabled", defaults.rootkitAwarenessEnabled);
  c.processCrossViewCheckEnabled =
      jsonBool(o, "processCrossViewCheckEnabled", defaults.processCrossViewCheckEnabled);
  c.kernelExtensionCheckEnabled =
      jsonBool(o, "kernelExtensionCheckEnabled", defaults.kernelExtensionCheckEnabled);
  c.integrityCheckEnabled = jsonBool(o, "integrityCheckEnabled", defaults.integrityCheckEnabled);
  // Phase 4 (EDR-Lite)
  c.edrLiteEnabled = jsonBool(o, "edrLiteEnabled", defaults.edrLiteEnabled);
  c.monitoringIntervalSeconds =
      jsonInt(o, "monitoringIntervalSeconds", defaults.monitoringIntervalSeconds);
  c.alertOnNewProcess = jsonBool(o, "alertOnNewProcess", defaults.alertOnNewProcess);
  c.alertOnNewPersistence = jsonBool(o, "alertOnNewPersistence", defaults.alertOnNewPersistence);
  c.alertOnIntegrityMismatch =
      jsonBool(o, "alertOnIntegrityMismatch", defaults.alertOnIntegrityMismatch);
  c.alertOnKernelExtensionChange =
      jsonBool(o, "alertOnKernelExtensionChange", defaults.alertOnKernelExtensionChange);
  return c;
}

// ============================================================================
// Store implementation
// ============================================================================
namespace {

QMutex g_storeMutex;
ScannerConfig g_config;
bool g_loaded = false;
QString g_cachedPath;

QString resolveConfigPath() {
  if (!g_cachedPath.isEmpty())
    return g_cachedPath;
  const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
  QDir().mkpath(dir);
  g_cachedPath = QDir(dir).absoluteFilePath("odysseus_config.json");
  return g_cachedPath;
}

bool writeJson(const QString& path, const QJsonObject& obj) {
  QFile f(path);
  if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
    qWarning().noquote() << "[Config] cannot write" << path << "—" << f.errorString();
    return false;
  }
  f.write(QJsonDocument(obj).toJson(QJsonDocument::Indented));
  f.close();
  return true;
}

ScannerConfig loadFromDisk() {
  const QString path = resolveConfigPath();
  QFile f(path);
  if (!f.exists()) {
    // First-run convenience: write a template so the user can find it.
    ScannerConfig defaults;
    if (writeJson(path, defaults.toJson()))
      qInfo().noquote() << "[Config] created default config at" << path;
    return defaults;
  }
  if (!f.open(QIODevice::ReadOnly)) {
    qWarning().noquote() << "[Config] cannot read" << path << "— using defaults ("
                         << f.errorString() << ")";
    return ScannerConfig{};
  }
  const QByteArray data = f.readAll();
  f.close();

  QJsonParseError err;
  const QJsonDocument doc = QJsonDocument::fromJson(data, &err);
  if (err.error != QJsonParseError::NoError || !doc.isObject()) {
    qWarning().noquote() << "[Config] parse error in" << path << "—" << err.errorString()
                         << "— using defaults";
    return ScannerConfig{};
  }
  return ScannerConfig::fromJson(doc.object());
}

void ensureLoaded() {
  if (g_loaded)
    return;
  g_config = loadFromDisk();
  g_loaded = true;
  qInfo().noquote().nospace() << "[Config] loaded "
                              << "yara=" << (g_config.yaraEnabled ? "on" : "off")
                              << " rep=" << (g_config.reputationAutoUpsert ? "on" : "off")
                              << " sign=" << (g_config.codeSigningEnabled ? "on" : "off")
                              << " verbose=" << (g_config.verboseLogging ? "on" : "off")
                              << " experimental=" << (g_config.experimentalRules ? "on" : "off")
                              << " sysmon=" << (g_config.systemMonitoringEnabled ? "on" : "off")
                              << " proc=" << (g_config.processScanEnabled ? "on" : "off")
                              << " persist=" << (g_config.persistenceScanEnabled ? "on" : "off")
                              << " heur="
                              << (g_config.suspiciousProcessHeuristicsEnabled ? "on" : "off")
                              << " rootkit=" << (g_config.rootkitAwarenessEnabled ? "on" : "off")
                              << " xview=" << (g_config.processCrossViewCheckEnabled ? "on" : "off")
                              << " kext=" << (g_config.kernelExtensionCheckEnabled ? "on" : "off")
                              << " integ=" << (g_config.integrityCheckEnabled ? "on" : "off")
                              << " edr=" << (g_config.edrLiteEnabled ? "on" : "off") << "("
                              << g_config.monitoringIntervalSeconds << "s)";
}

}  // namespace

namespace ScannerConfigStore {

const ScannerConfig& current() {
  QMutexLocker lock(&g_storeMutex);
  ensureLoaded();
  return g_config;
}

bool set(const ScannerConfig& c) {
  QMutexLocker lock(&g_storeMutex);
  g_config = c;
  g_loaded = true;
  const bool ok = writeJson(resolveConfigPath(), c.toJson());
  if (ok)
    qInfo().noquote() << "[Config] saved updates to" << resolveConfigPath();
  return ok;
}

void reload() {
  QMutexLocker lock(&g_storeMutex);
  g_config = loadFromDisk();
  g_loaded = true;
}

QString configPath() {
  QMutexLocker lock(&g_storeMutex);
  return resolveConfigPath();
}

ScannerConfig resetToDefaults() {
  QMutexLocker lock(&g_storeMutex);
  g_config = ScannerConfig{};
  g_loaded = true;
  writeJson(resolveConfigPath(), g_config.toJson());
  qInfo() << "[Config] reset to factory defaults";
  return g_config;
}

}  // namespace ScannerConfigStore
