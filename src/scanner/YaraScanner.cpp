// ============================================================================
// YaraScanner.cpp  –  libyara wrapper for Phase 1 detection pass
//
// Compiles in two modes:
//
//   • ODY_HAS_YARA defined  → real implementation linking against libyara.
//   • ODY_HAS_YARA undefined → stub: initialize() returns false, scanFile()
//                              always returns an empty YaraScanResult. The
//                              binary still builds and runs end-to-end.
//
// This dual-mode pattern matches AnomalyDetector.cpp / EmberDetector.cpp in
// this codebase: optional native deps never block a clean build.
// ============================================================================

#include "scanner/YaraScanner.h"

#include <QDebug>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QMutex>
#include <QMutexLocker>
#include <atomic>
#include <cstring>

// ============================================================================
// Real implementation (linked against libyara)
// ============================================================================
#ifdef ODY_HAS_YARA

extern "C" {
#include <yara.h>
}

namespace {

// libyara's global initialization is one-time. Guard it with std::atomic so
// initialize() is safe to call from any thread, but the library is only
// initialized once per process.
std::atomic<bool> g_yaraLibInitialized{false};
QMutex g_yaraInitMutex;

YR_RULES* g_rules = nullptr;  // compiled rule set, shared across threads
int g_ruleCount = 0;
bool g_available = false;

// ----------------------------------------------------------------------------
// Helpers to extract metadata strings from a YR_RULE (libyara API)
// ----------------------------------------------------------------------------
QString getMetaString(YR_RULE* rule, const char* key) {
  YR_META* meta;
  yr_rule_metas_foreach(rule, meta) {
    if (meta && meta->identifier && std::strcmp(meta->identifier, key) == 0) {
      if (meta->type == META_TYPE_STRING && meta->string)
        return QString::fromUtf8(meta->string);
      if (meta->type == META_TYPE_INTEGER)
        return QString::number(meta->integer);
    }
  }
  return {};
}

QStringList getRuleTags(YR_RULE* rule) {
  QStringList tags;
  const char* t;
  yr_rule_tags_foreach(rule, t) {
    if (t)
      tags.append(QString::fromUtf8(t));
  }
  return tags;
}

// ----------------------------------------------------------------------------
// scanCallback  –  invoked once per matched (or unmatched) rule.
// We accumulate matches into a std::vector passed via user_data.
// ----------------------------------------------------------------------------
struct CallbackCtx {
  QVector<YaraMatch>* out;
};

int scanCallback(YR_SCAN_CONTEXT* /*context*/, int message, void* messageData, void* userData) {
  if (message != CALLBACK_MSG_RULE_MATCHING)
    return CALLBACK_CONTINUE;

  auto* ctx = static_cast<CallbackCtx*>(userData);
  auto* rule = static_cast<YR_RULE*>(messageData);
  if (!ctx || !ctx->out || !rule || !rule->identifier)
    return CALLBACK_CONTINUE;

  YaraMatch m;
  m.ruleName = QString::fromUtf8(rule->identifier);
  if (rule->ns && rule->ns->name)
    m.ruleNamespace = QString::fromUtf8(rule->ns->name);
  m.family = getMetaString(rule, "family");
  m.description = getMetaString(rule, "description");
  m.severity = getMetaString(rule, "severity").toLower();
  m.tags = getRuleTags(rule);

  ctx->out->append(std::move(m));
  return CALLBACK_CONTINUE;
}

// ----------------------------------------------------------------------------
// Per-file compile-error callback (verbose mode only). libyara invokes this
// for every error/warning encountered during yr_compiler_add_file().
// ----------------------------------------------------------------------------
void yaraCompilerCallback(
    int errorLevel,
    const char* fileName,
    int lineNumber,
    const YR_RULE* /*rule*/,
    const char* message,
    void* userData) {
  int* errCount = static_cast<int*>(userData);
  if (errCount)
    (*errCount) += 1;

  const QString file =
      fileName ? QFileInfo(QString::fromUtf8(fileName)).fileName() : QStringLiteral("(unknown)");
  if (errorLevel == YARA_ERROR_LEVEL_ERROR) {
    qWarning().noquote() << QString("[YARA] ERROR in %1:%2 — %3")
                                .arg(file)
                                .arg(lineNumber)
                                .arg(
                                    message ? QString::fromUtf8(message)
                                            : QStringLiteral("(no message)"));
  } else {
    qInfo().noquote() << QString("[YARA] warning in %1:%2 — %3")
                             .arg(file)
                             .arg(lineNumber)
                             .arg(
                                 message ? QString::fromUtf8(message)
                                         : QStringLiteral("(no message)"));
  }
}

// ----------------------------------------------------------------------------
// Compile every .yar / .yara file under opts.rulesDir into a single YR_RULES
// set. Returns the number of rules successfully compiled. Honors
// includeExperimental (skip <rulesDir>/<experimentalSubdir>) and
// maxCompileErrors (bail when exceeded).
// ----------------------------------------------------------------------------
int compileRulesDir(const YaraInitOptions& opts, YR_RULES** outRules) {
  YR_COMPILER* compiler = nullptr;
  if (yr_compiler_create(&compiler) != ERROR_SUCCESS || !compiler) {
    qWarning() << "[YARA] yr_compiler_create failed (out of memory?)";
    return 0;
  }

  int verboseErrCount = 0;
  if (opts.verbose) {
    // Register our callback so EVERY compile error is logged with file:line.
    yr_compiler_set_callback(compiler, yaraCompilerCallback, &verboseErrCount);
  }

  QDir dir(opts.rulesDir);
  if (!dir.exists()) {
    qWarning().noquote() << "[YARA] rules directory does not exist:" << opts.rulesDir
                         << "— YARA pass disabled. Drop .yar files there to enable.";
    yr_compiler_destroy(compiler);
    return 0;
  }

  // Build the file list, optionally filtering out the experimental subdir.
  QString experimentalAbs;
  if (!opts.includeExperimental && !opts.experimentalSubdir.isEmpty()) {
    experimentalAbs = QDir(opts.rulesDir).absoluteFilePath(opts.experimentalSubdir);
  }

  const QStringList exts = {"*.yar", "*.yara"};
  QFileInfoList files;
  int skippedExperimental = 0;
  QDirIterator it(opts.rulesDir, exts, QDir::Files, QDirIterator::Subdirectories);
  while (it.hasNext()) {
    it.next();
    const QFileInfo fi = it.fileInfo();
    if (!experimentalAbs.isEmpty() && fi.absoluteFilePath().startsWith(experimentalAbs)) {
      ++skippedExperimental;
      continue;
    }
    files.append(fi);
  }

  if (skippedExperimental > 0) {
    qInfo().noquote() << QString(
                             "[YARA] skipped %1 experimental rule file(s) under %2 "
                             "(set experimentalRules=true in odysseus_config.json to enable)")
                             .arg(skippedExperimental)
                             .arg(experimentalAbs);
  }

  if (files.isEmpty()) {
    qWarning().noquote() << "[YARA] no .yar/.yara files found under" << opts.rulesDir;
    yr_compiler_destroy(compiler);
    return 0;
  }

  int totalErrors = 0;
  int filesAttempted = 0;
  int filesOk = 0;
  for (const QFileInfo& fi : files) {
    if (totalErrors >= opts.maxCompileErrors) {
      qWarning().noquote() << QString(
                                  "[YARA] hit maxCompileErrors=%1 — stopping compile pass "
                                  "(remaining %2 file(s) skipped)")
                                  .arg(opts.maxCompileErrors)
                                  .arg(files.size() - filesAttempted);
      break;
    }
    ++filesAttempted;
    const QByteArray pathBytes = fi.absoluteFilePath().toUtf8();
    FILE* f = std::fopen(pathBytes.constData(), "rb");
    if (!f) {
      qWarning().noquote() << "[YARA] could not open rule file:" << fi.absoluteFilePath();
      continue;
    }
    const QByteArray nsBytes = fi.completeBaseName().toUtf8();
    const int errors =
        yr_compiler_add_file(compiler, f, nsBytes.constData(), pathBytes.constData());
    std::fclose(f);
    if (errors > 0) {
      qWarning().noquote()
          << QString(
                 "[YARA] %1 compile error(s) in %2 — rule(s) skipped"
                 "%3")
                 .arg(errors)
                 .arg(fi.fileName())
                 .arg(opts.verbose ? "" : " (set verboseLogging=true for line-level detail)");
      totalErrors += errors;
    } else {
      ++filesOk;
    }
  }

  YR_RULES* compiled = nullptr;
  if (yr_compiler_get_rules(compiler, &compiled) != ERROR_SUCCESS) {
    qWarning() << "[YARA] yr_compiler_get_rules failed — no rules loaded";
    yr_compiler_destroy(compiler);
    return 0;
  }
  yr_compiler_destroy(compiler);

  // Count rules in the compiled set
  int n = 0;
  YR_RULE* rule = nullptr;
  yr_rules_foreach(compiled, rule) {
    (void)rule;
    ++n;
  }

  *outRules = compiled;
  qInfo().noquote() << QString(
                           "[YARA] compile pass complete: %1 rule(s) from %2 file(s) ok, "
                           "%3 file(s) had errors, %4 total error(s)")
                           .arg(n)
                           .arg(filesOk)
                           .arg(filesAttempted - filesOk)
                           .arg(totalErrors);
  return n;
}

}  // anonymous namespace

namespace YaraScanner {

bool initialize(const YaraInitOptions& opts) {
  QMutexLocker lock(&g_yaraInitMutex);
  if (g_available)
    return true;
  if (g_rules)
    return true;  // partial state — treat as init done

  if (!g_yaraLibInitialized.load()) {
    if (yr_initialize() != ERROR_SUCCESS) {
      qWarning() << "[YARA] yr_initialize failed — disabling YARA pass";
      return false;
    }
    g_yaraLibInitialized.store(true);
  }

  YR_RULES* compiled = nullptr;
  const int n = compileRulesDir(opts, &compiled);
  if (n <= 0 || !compiled) {
    // No rules — leave library initialized but mark unavailable.
    return false;
  }

  g_rules = compiled;
  g_ruleCount = n;
  g_available = true;
  qInfo().noquote() << QString("[YARA] active with %1 rule(s) from %2%3")
                           .arg(n)
                           .arg(opts.rulesDir)
                           .arg(opts.includeExperimental ? " [experimental ON]" : "");
  return true;
}

bool initialize(const QString& rulesDir) {
  YaraInitOptions opts;
  opts.rulesDir = rulesDir;
  return initialize(opts);
}

bool isAvailable() {
  return g_available && g_rules != nullptr;
}
int ruleCount() {
  return g_ruleCount;
}

YaraScanResult scanFile(const QString& filePath) {
  YaraScanResult res;
  if (!isAvailable())
    return res;

  CallbackCtx ctx;
  ctx.out = &res.matches;

  const QByteArray pathBytes = filePath.toUtf8();
  const int rc = yr_rules_scan_file(
      g_rules,
      pathBytes.constData(),
      /*flags*/ 0,
      &scanCallback,
      &ctx,
      /*timeout sec*/ 10);
  if (rc != ERROR_SUCCESS) {
    res.hadError = true;
    res.errorString = QString("yr_rules_scan_file rc=%1").arg(rc);
    // Note: most non-success codes here are file-access related (permission
    // denied, file vanished mid-scan). Don't escalate to qWarning per file
    // or we'll spam the log on a normal scan; let the caller decide.
  }
  return res;
}

void shutdown() {
  QMutexLocker lock(&g_yaraInitMutex);
  if (g_rules) {
    yr_rules_destroy(g_rules);
    g_rules = nullptr;
  }
  if (g_yaraLibInitialized.load()) {
    yr_finalize();
    g_yaraLibInitialized.store(false);
  }
  g_available = false;
  g_ruleCount = 0;
}

}  // namespace YaraScanner

// ============================================================================
// Stub implementation (libyara not present at build time)
// ============================================================================
#else   // !ODY_HAS_YARA

namespace YaraScanner {

static bool g_loggedOnce = false;

static void logLibyaraMissing() {
  if (g_loggedOnce)
    return;
  g_loggedOnce = true;
  qWarning().noquote()
      << "[YARA] libyara is NOT linked in this build — YARA rule scanning is disabled.\n"
      << "       Hash-based and AI-based detection still work normally.\n"
      << "       To enable YARA:\n"
      << "         macOS  : brew install yara && cmake --build build --clean-first\n"
      << "         Debian : sudo apt install libyara-dev && rebuild\n"
      << "         Fedora : sudo dnf install yara-devel && rebuild";
}

bool initialize(const YaraInitOptions& /*opts*/) {
  logLibyaraMissing();
  return false;
}

bool initialize(const QString& /*rulesDir*/) {
  logLibyaraMissing();
  return false;
}

bool isAvailable() {
  return false;
}
int ruleCount() {
  return 0;
}

YaraScanResult scanFile(const QString& /*filePath*/) {
  return YaraScanResult{};  // empty, no matches, no error
}

void shutdown() {}

}  // namespace YaraScanner

#endif  // ODY_HAS_YARA
