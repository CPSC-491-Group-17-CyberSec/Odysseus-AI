// ============================================================================
// PersistenceScanner.cpp
//
// Strategy:
//   • LaunchAgent / LaunchDaemon plists: convert to JSON via `plutil
//     -convert json -o - <path>` (a system tool always present on macOS),
//     then parse with QJsonDocument. plutil handles binary, XML, and JSON
//     plist formats transparently.
//   • cron: shell out to `crontab -l` for the current user; read system
//     crontabs from disk.
//   • Linux: cron + systemd unit files via plain text reads.
//
// Why plutil instead of a CFPropertyList linkage:
//   We avoid linking against CoreFoundation just to parse plists. plutil is
//   bundled with macOS since 10.4, runs in <10 ms per file, and its JSON
//   output is trivial to consume. Same approach used by many security tools
//   (osquery's launchd table, KnockKnock).
//
// Severity assignment:
//   • RunAtLoad=true OR KeepAlive=true                   → medium
//   • Program path under /tmp, /var/tmp, ~/Downloads     → high
//   • Target executable missing on disk                  → high
//   • Otherwise                                          → low
// ============================================================================

#include "monitor/PersistenceScanner.h"

#include <QDebug>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QRegularExpression>
#include <QSettings>
#include <QStandardPaths>
#include <QtGlobal>

namespace PersistenceScanner {

namespace {

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
bool pathLooksSuspicious(const QString& path) {
  if (path.isEmpty())
    return false;
  const QString p = path;
  if (p.startsWith("/tmp/"))
    return true;
  if (p.startsWith("/var/tmp/"))
    return true;
  if (p.startsWith("/private/tmp/"))
    return true;
  if (p.startsWith("/private/var/tmp/"))
    return true;
  if (p.contains("/Downloads/"))
    return true;
  // Hidden directory anywhere along the path (segment starts with '.', not just '.')
  for (const QString& seg : p.split('/', Qt::SkipEmptyParts)) {
    if (seg.size() > 1 && seg.startsWith('.') && seg != "..")
      return true;
  }
  return false;
}

QString jsonString(const QJsonObject& o, const QString& key) {
  if (!o.contains(key))
    return {};
  const auto v = o.value(key);
  return v.isString() ? v.toString() : QString();
}
bool jsonBool(const QJsonObject& o, const QString& key, bool fallback = false) {
  if (!o.contains(key))
    return fallback;
  const auto v = o.value(key);
  return v.isBool() ? v.toBool() : fallback;
}
QStringList jsonStringList(const QJsonObject& o, const QString& key) {
  QStringList out;
  if (!o.contains(key))
    return out;
  const auto v = o.value(key);
  if (!v.isArray())
    return out;
  for (const auto& item : v.toArray())
    if (item.isString())
      out.append(item.toString());
  return out;
}

// Run a shell tool with a 5-second cap. Returns exit code or -1 on failure.
struct ToolResult {
  int rc = -1;
  QString out;
  QString err;
};
ToolResult runTool(const QString& program, const QStringList& args) {
  ToolResult r;
  QProcess p;
  p.start(program, args);
  if (!p.waitForStarted(1500))
    return r;
  if (!p.waitForFinished(5000)) {
    p.kill();
    p.waitForFinished(500);
    return r;
  }
  r.rc = p.exitCode();
  r.out = QString::fromUtf8(p.readAllStandardOutput());
  r.err = QString::fromUtf8(p.readAllStandardError());
  return r;
}

void rateItem(PersistenceItem& it) {
  bool high = false, medium = false;

  if (pathLooksSuspicious(it.program))
    high = true;
  if (!it.program.isEmpty() && !QFile::exists(it.program)) {
    it.notes.append("Target executable missing on disk");
    high = true;
  }
  if (it.runAtLoad || it.keepAlive)
    medium = true;

  if (high)
    it.severity = "high";
  else if (medium)
    it.severity = "medium";
  else
    it.severity = "low";
}

}  // namespace

// ============================================================================
// macOS implementation
// ============================================================================
#if defined(Q_OS_MACOS)

// Parse a single launchd plist into a PersistenceItem.
// Returns std::nullopt-style: empty Label means we couldn't parse it.
static PersistenceItem parseLaunchdPlist(
    const QString& path, const QString& itemType, int& errorsLogged) {
  PersistenceItem it;
  it.type = itemType;
  it.filePath = path;
  it.lastModified = QFileInfo(path).lastModified();

  const ToolResult t = runTool("/usr/bin/plutil", {"-convert", "json", "-o", "-", path});
  if (t.rc != 0 || t.out.isEmpty()) {
    ++errorsLogged;
    return it;  // Label empty → caller will skip it
  }

  QJsonParseError jerr;
  const QJsonDocument doc = QJsonDocument::fromJson(t.out.toUtf8(), &jerr);
  if (jerr.error != QJsonParseError::NoError || !doc.isObject()) {
    ++errorsLogged;
    return it;
  }
  const QJsonObject obj = doc.object();

  it.label = jsonString(obj, "Label");
  it.runAtLoad = jsonBool(obj, "RunAtLoad");
  it.keepAlive = jsonBool(obj, "KeepAlive") || obj.value("KeepAlive").isObject();  // dict form
  it.program = jsonString(obj, "Program");
  it.programArgs = jsonStringList(obj, "ProgramArguments");

  // If Program is unset but ProgramArguments is, argv[0] is the executable.
  if (it.program.isEmpty() && !it.programArgs.isEmpty())
    it.program = it.programArgs.first();

  // Build a human-readable schedule hint
  if (it.runAtLoad)
    it.scheduleHint = "RunAtLoad";
  if (it.keepAlive)
    it.scheduleHint += (it.scheduleHint.isEmpty() ? "" : " + ") + QString("KeepAlive");
  if (obj.contains("StartInterval"))
    it.scheduleHint += QString(" StartInterval=%1s").arg(obj.value("StartInterval").toInt());
  if (obj.contains("StartCalendarInterval"))
    it.scheduleHint += " StartCalendarInterval";

  if (it.label.isEmpty())
    it.label = QFileInfo(path).completeBaseName();

  rateItem(it);
  return it;
}

static void scanLaunchdDir(
    const QString& dir, const QString& itemType, QVector<PersistenceItem>& out, int& errorsLogged) {
  QDir d(dir);
  if (!d.exists())
    return;

  int found = 0;
  for (const QFileInfo& fi : d.entryInfoList({"*.plist"}, QDir::Files, QDir::Name)) {
    PersistenceItem it = parseLaunchdPlist(fi.absoluteFilePath(), itemType, errorsLogged);
    if (!it.label.isEmpty()) {
      out.append(std::move(it));
      ++found;
    }
  }
  qInfo().noquote()
      << QString("[SysMon] %1: %2 item(s) under %3").arg(itemType).arg(found).arg(dir);
}

static void scanCron(QVector<PersistenceItem>& out, int& /*errorsLogged*/) {
  // ── Current user crontab via `crontab -l` ──────────────────────────
  const ToolResult t = runTool("crontab", {"-l"});
  if (t.rc == 0 && !t.out.isEmpty()) {
    int n = 0;
    for (const QString& line : t.out.split('\n')) {
      const QString trimmed = line.trimmed();
      if (trimmed.isEmpty() || trimmed.startsWith('#'))
        continue;

      PersistenceItem it;
      it.type = "UserCron";
      it.label = QString("crontab line %1").arg(++n);
      it.scheduleHint = trimmed;
      // Best-effort: extract program by skipping the 5 schedule fields
      const QStringList parts = trimmed.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
      if (parts.size() >= 6) {
        it.program = parts[5];
        it.programArgs = parts.mid(5);
      }
      rateItem(it);
      out.append(std::move(it));
    }
    qInfo().noquote() << QString("[SysMon] UserCron: %1 active crontab line(s)").arg(n);
  }

  // ── /etc/crontab (system) ──────────────────────────────────────────
  const QStringList systemFiles = {
      "/etc/crontab",
  };
  const QStringList systemDirs = {
      "/etc/cron.d",
      "/etc/periodic",
      "/etc/periodic/daily",
      "/etc/periodic/weekly",
      "/etc/periodic/monthly",
  };

  for (const QString& f : systemFiles) {
    QFile file(f);
    if (!file.exists())
      continue;
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
      continue;
    const QString text = QString::fromUtf8(file.readAll());
    file.close();
    int n = 0;
    for (const QString& line : text.split('\n')) {
      const QString tr = line.trimmed();
      if (tr.isEmpty() || tr.startsWith('#'))
        continue;
      PersistenceItem it;
      it.type = "SystemCron";
      it.filePath = f;
      it.label = QString("%1 line %2").arg(QFileInfo(f).fileName()).arg(++n);
      it.scheduleHint = tr;
      rateItem(it);
      out.append(std::move(it));
    }
  }

  for (const QString& d : systemDirs) {
    QDir dir(d);
    if (!dir.exists())
      continue;
    for (const QFileInfo& fi : dir.entryInfoList(QDir::Files)) {
      PersistenceItem it;
      it.type = "SystemCron";
      it.filePath = fi.absoluteFilePath();
      it.label = fi.fileName();
      it.scheduleHint = "scheduled (cron.d / periodic)";
      it.lastModified = fi.lastModified();
      rateItem(it);
      out.append(std::move(it));
    }
  }
}

bool scan(QVector<PersistenceItem>& out, int& errorsLogged) {
  errorsLogged = 0;

  const QString home = QDir::homePath();

  scanLaunchdDir(home + "/Library/LaunchAgents", "LaunchAgent", out, errorsLogged);
  scanLaunchdDir("/Library/LaunchAgents", "LaunchAgent", out, errorsLogged);
  scanLaunchdDir("/Library/LaunchDaemons", "LaunchDaemon", out, errorsLogged);
  scanCron(out, errorsLogged);

  if (errorsLogged > 0) {
    qWarning().noquote() << QString(
                                "[SysMon] %1 plist parse failure(s) suppressed "
                                "(possibly malformed or not a valid launchd plist)")
                                .arg(errorsLogged);
  }
  return true;
}

// ============================================================================
// Linux implementation
// ============================================================================
#elif defined(Q_OS_LINUX)

static void scanCronLinux(QVector<PersistenceItem>& out) {
  // /etc/crontab + /etc/cron.{d,daily,hourly,weekly,monthly}
  const QStringList systemFiles = {"/etc/crontab"};
  const QStringList systemDirs = {
      "/etc/cron.d",
      "/etc/cron.daily",
      "/etc/cron.hourly",
      "/etc/cron.weekly",
      "/etc/cron.monthly",
  };

  for (const QString& f : systemFiles) {
    QFile file(f);
    if (!file.exists() || !file.open(QIODevice::ReadOnly))
      continue;
    const QString text = QString::fromUtf8(file.readAll());
    file.close();
    int n = 0;
    for (const QString& line : text.split('\n')) {
      const QString tr = line.trimmed();
      if (tr.isEmpty() || tr.startsWith('#'))
        continue;
      PersistenceItem it;
      it.type = "SystemCron";
      it.filePath = f;
      it.label = QString("%1 line %2").arg(QFileInfo(f).fileName()).arg(++n);
      it.scheduleHint = tr;
      rateItem(it);
      out.append(std::move(it));
    }
  }

  for (const QString& d : systemDirs) {
    QDir dir(d);
    if (!dir.exists())
      continue;
    for (const QFileInfo& fi : dir.entryInfoList(QDir::Files)) {
      PersistenceItem it;
      it.type = "SystemCron";
      it.filePath = fi.absoluteFilePath();
      it.label = fi.fileName();
      it.scheduleHint = "scheduled (cron.d)";
      it.lastModified = fi.lastModified();
      rateItem(it);
      out.append(std::move(it));
    }
  }

  // Current user crontab. crontab is part of cron / cronie / dcron — most
  // distros ship one of those. If the binary isn't installed we just log
  // and move on; the system-wide /etc/crontab + /etc/cron.d enumeration
  // above still works.
  QProcess p;
  p.start("crontab", {"-l"});
  if (!p.waitForStarted(1500)) {
    qInfo() << "[SysMon] crontab binary not available on this system — "
               "skipping per-user cron enumeration";
    return;
  }
  if (p.waitForFinished(5000) && p.exitCode() == 0) {
    const QString text = QString::fromUtf8(p.readAllStandardOutput());
    int n = 0;
    for (const QString& line : text.split('\n')) {
      const QString tr = line.trimmed();
      if (tr.isEmpty() || tr.startsWith('#'))
        continue;
      PersistenceItem it;
      it.type = "UserCron";
      it.label = QString("crontab line %1").arg(++n);
      it.scheduleHint = tr;
      rateItem(it);
      out.append(std::move(it));
    }
  }
}

static void scanSystemdUnits(
    const QString& dir, const QString& itemType, QVector<PersistenceItem>& out) {
  QDir d(dir);
  if (!d.exists())
    return;

  for (const QFileInfo& fi : d.entryInfoList({"*.service"}, QDir::Files)) {
    QFile f(fi.absoluteFilePath());
    if (!f.open(QIODevice::ReadOnly))
      continue;
    const QString text = QString::fromUtf8(f.readAll());
    f.close();

    PersistenceItem it;
    it.type = itemType;
    it.filePath = fi.absoluteFilePath();
    it.label = fi.completeBaseName();
    it.lastModified = fi.lastModified();

    for (const QString& line : text.split('\n')) {
      const QString tr = line.trimmed();
      if (tr.startsWith("ExecStart=")) {
        const QString cmd = tr.mid(QString("ExecStart=").size()).trimmed();
        it.programArgs = cmd.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
        if (!it.programArgs.isEmpty())
          it.program = it.programArgs.first();
      } else if (tr.startsWith("WantedBy=")) {
        it.scheduleHint = tr;
        if (tr.contains("multi-user.target") || tr.contains("default.target"))
          it.runAtLoad = true;
      }
    }
    rateItem(it);
    out.append(std::move(it));
  }
}

bool scan(QVector<PersistenceItem>& out, int& errorsLogged) {
  errorsLogged = 0;
  scanSystemdUnits("/etc/systemd/system", "SystemdUnit", out);
  scanSystemdUnits(QDir::homePath() + "/.config/systemd/user", "SystemdUserUnit", out);
  scanCronLinux(out);
  return true;
}

// ============================================================================
// Windows implementation — registry Run keys + Startup folders (read-only)
// ============================================================================
#elif defined(Q_OS_WIN)

// Walk a registry "Run" key via QSettings::NativeFormat. On Windows this
// uses the native registry API under the hood (no shell-out, no admin
// needed for HKCU; HKLM read works for any user).
static void scanWindowsRunKey(
    const QString& hivePath, const QString& type, QVector<PersistenceItem>& out) {
  QSettings settings(hivePath, QSettings::NativeFormat);
  const QStringList keys = settings.allKeys();
  for (const QString& key : keys) {
    const QString cmd = settings.value(key).toString().trimmed();
    if (cmd.isEmpty())
      continue;

    PersistenceItem it;
    it.type = type;
    it.label = key;
    it.filePath = hivePath;
    it.runAtLoad = true;
    it.scheduleHint = "RunAtLogon (registry)";

    // Parse "<program>" or "C:\\path\\foo.exe arg1 arg2" into program +
    // programArgs. Windows command lines can quote the program path.
    if (cmd.startsWith('"')) {
      const int close = cmd.indexOf('"', 1);
      if (close > 0) {
        it.program = cmd.mid(1, close - 1);
        const QString rest = cmd.mid(close + 1).trimmed();
        if (!rest.isEmpty())
          it.programArgs = QStringList{rest};
      } else {
        it.program = cmd;
      }
    } else {
      const int sp = cmd.indexOf(' ');
      it.program = (sp > 0) ? cmd.left(sp) : cmd;
      if (sp > 0)
        it.programArgs = QStringList{cmd.mid(sp + 1).trimmed()};
    }

    // Sanity: warn if the resolved program file is missing.
    if (!it.program.isEmpty() && !QFile::exists(it.program))
      it.notes.append("Target executable missing on disk");

    rateItem(it);
    out.append(std::move(it));
  }
}

// Walk a Windows "Startup" folder. Most entries are .lnk shortcuts;
// resolving the .lnk target requires IShellLink COM, which we deliberately
// skip in this read-only first pass — recording the .lnk path itself is
// enough to surface "something runs at login from this folder".
static void scanStartupFolder(
    const QString& folderPath, const QString& type, QVector<PersistenceItem>& out) {
  QDir d(folderPath);
  if (!d.exists())
    return;

  int found = 0;
  for (const QFileInfo& fi : d.entryInfoList(QDir::Files | QDir::NoDotAndDotDot, QDir::Name)) {
    PersistenceItem it;
    it.type = type;
    it.filePath = fi.absoluteFilePath();
    it.label = fi.fileName();
    it.lastModified = fi.lastModified();
    it.runAtLoad = true;
    it.scheduleHint = "Startup folder entry (RunAtLogon)";
    it.program = fi.absoluteFilePath();  // .lnk path; target unresolved
    if (fi.suffix().toLower() == "lnk")
      it.notes.append(
          "Shortcut target not resolved "
          "(IShellLink read deferred to a later pass)");
    rateItem(it);
    out.append(std::move(it));
    ++found;
  }
  qInfo().noquote()
      << QString("[SysMon] %1: %2 entry/entries under %3").arg(type).arg(found).arg(folderPath);
}

bool scan(QVector<PersistenceItem>& out, int& errorsLogged) {
  errorsLogged = 0;

  // ── Registry Run keys ─────────────────────────────────────────────
  scanWindowsRunKey(
      "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "Registry/Run/HKCU",
      out);
  scanWindowsRunKey(
      "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "Registry/Run/HKLM",
      out);
  // RunOnce keys — fire once and remove themselves; analyst-relevant.
  scanWindowsRunKey(
      "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "Registry/RunOnce/HKCU",
      out);
  scanWindowsRunKey(
      "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "Registry/RunOnce/HKLM",
      out);

  // ── Startup folders ────────────────────────────────────────────────
  const QString home = QDir::homePath();
  scanStartupFolder(
      home + "/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
      "Startup/CurrentUser",
      out);
  scanStartupFolder(
      "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup", "Startup/AllUsers", out);

  qInfo().noquote()
      << QString("[SysMon] Windows persistence scan complete — %1 item(s)").arg(out.size());
  return true;
}

// ============================================================================
// Stub for any other platform
// ============================================================================
#else

bool scan(QVector<PersistenceItem>& /*out*/, int& errorsLogged) {
  errorsLogged = 0;
  qInfo() << "[SysMon] persistence scanning not implemented on this platform";
  return false;
}

#endif

}  // namespace PersistenceScanner
