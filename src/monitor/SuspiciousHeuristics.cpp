// ============================================================================
// SuspiciousHeuristics.cpp
//
// Each heuristic is its own small function so they can be unit-tested
// individually and re-used by the UI ("why was this process flagged?").
//
// Weighting philosophy:
//   • PathFromTmp / PathHidden            — strong signal (40)
//   • ExeMissing                           — strong signal (50)
//   • UnsignedExecutable + bad path        — multiplicative (combined 70)
//   • RootFromUserPath                     — strong signal (40)
//   • RandomLookingName                    — weak signal (15) — false positives
//                                            common (browser sandbox helpers)
//   • SuspiciousCmdLine                    — medium signal (30)
//
// We never single-flag on RandomLookingName alone — that's a known
// false-positive trap.  Other heuristics either stand alone or compound.
// ============================================================================

#include "monitor/SuspiciousHeuristics.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QtGlobal>
#include <algorithm>

#include "reputation/CodeSigning.h"

namespace SuspiciousHeuristics {

// ----------------------------------------------------------------------------
// Path-based heuristics
// ----------------------------------------------------------------------------
QString testPath(const ProcessInfo& p) {
  const QString& path = p.exePath;
  if (path.isEmpty())
    return {};

  // Lowercase + forward-slash normalization so the same heuristics work
  // against both Unix (/tmp/...) and Windows (C:\Users\...\Temp\...) paths.
  QString lower = path.toLower();
  lower.replace('\\', '/');

  // ── Temp / staging directories ─────────────────────────────────────
  // Unix
  if (lower.startsWith("/tmp/") || lower.startsWith("/var/tmp/") ||
      lower.startsWith("/private/tmp/") || lower.startsWith("/private/var/tmp/")) {
    return QString("Executable runs from temp directory: %1").arg(path);
  }
  // Windows: %TEMP% lives under either the user's local AppData or
  // C:\Windows\Temp. Both are classic dropper staging areas.
  if (lower.contains("/appdata/local/temp/") || lower.contains("/windows/temp/")) {
    return QString("Executable runs from Windows temp directory: %1").arg(path);
  }

  // ── Downloads ──────────────────────────────────────────────────────
  if (lower.contains("/downloads/"))
    return QString("Executable runs from Downloads: %1").arg(path);

  // ── Roaming AppData (Windows-only) ─────────────────────────────────
  // Legitimate apps install here too (Slack, Discord). Lower severity
  // than Temp / Downloads but still worth surfacing.
  if (lower.contains("/appdata/roaming/")) {
    // Skip the well-known Microsoft / WindowsApps subtree to avoid
    // false-positives for OS components that live there.
    if (!lower.contains("/appdata/roaming/microsoft/")) {
      return QString("Executable runs from AppData\\Roaming: %1").arg(path);
    }
  }

  // ── Hidden directory anywhere on the path (Unix-style dotfiles) ────
  for (const QString& seg : path.split('/', Qt::SkipEmptyParts)) {
    if (seg.size() > 1 && seg.startsWith('.') && seg != "..")
      return QString("Executable lives under hidden directory '%1'").arg(seg);
  }
  return {};
}

QString testExeMissing(const ProcessInfo& p) {
  if (p.exeMissing)
    return QString("Executable file no longer exists on disk (deleted while running)");
  return {};
}

// Score how "random-looking" a string is. 0 = clearly word-shaped, 1.0 = pure
// random. Heuristic: ratio of digits + ratio of non-vowel/non-consonant runs.
static double randomnessScore(const QString& s) {
  if (s.length() < 5)
    return 0.0;  // too short to judge

  int digits = 0;
  int letters = 0;
  int vowels = 0;
  int caseFlips = 0;
  QChar prev;
  for (int i = 0; i < s.size(); ++i) {
    const QChar c = s[i];
    if (c.isDigit())
      ++digits;
    if (c.isLetter()) {
      ++letters;
      const QChar lc = c.toLower();
      if (QString("aeiouy").contains(lc))
        ++vowels;
    }
    if (i > 0 && prev.isLetter() && c.isLetter() && (prev.isUpper() != c.isUpper()))
      ++caseFlips;
    prev = c;
  }

  const double n = static_cast<double>(s.length());
  const double digitRatio = digits / n;
  const double vowelRatio = letters > 0 ? double(vowels) / letters : 0.5;
  const double caseRatio = caseFlips / n;

  // High digit ratio → looks random.
  // Vowel ratio ≪ 0.3 → looks random (real names average ~0.4).
  // High case-flip ratio → looks random (e.g. aB7xC2zF9).
  double score = 0.0;
  if (digitRatio > 0.3)
    score += 0.4;
  if (vowelRatio < 0.2 && letters > 4)
    score += 0.4;
  if (caseRatio > 0.4)
    score += 0.3;
  return std::min(1.0, score);
}

QString testRandomName(const ProcessInfo& p) {
  // Apply only to the process name (not full path). 16-char macOS truncation
  // means we sometimes see arbitrary-looking names from legit binaries — keep
  // this conservative.
  const QString name = p.name;
  if (name.length() < 6)
    return {};
  const double r = randomnessScore(name);
  if (r >= 0.6)
    return QString("Process name '%1' looks randomly generated").arg(name);
  return {};
}

QString testCmdLine(const ProcessInfo& p) {
  if (p.cmdLine.isEmpty() || p.cmdLine == "(restricted)")
    return {};
  const QString cl = p.cmdLine;

  // Patterns drawn from MITRE ATT&CK common-loader inventory.
  static const QStringList badPatterns = {
      "powershell -enc",
      "powershell -e ",
      "powershell.exe -enc",
      "-EncodedCommand",
      "base64 -d",
      "curl http",
      "curl https",
      "wget http",
      "/bin/sh -i",
      "/bin/bash -i",
      "bash -c \"$(curl",
      "nc -e",
      "ncat -e",
      "python -c \"import socket",
  };

  for (const QString& pat : badPatterns) {
    if (cl.contains(pat, Qt::CaseInsensitive)) {
      return QString("Suspicious command-line pattern: '%1'").arg(pat);
    }
  }
  // pipe-to-shell: `... | sh` or `... | bash`
  static const QRegularExpression pipeShRx(
      R"(\|\s*(?:sh|bash|zsh)\b)", QRegularExpression::CaseInsensitiveOption);
  if (pipeShRx.match(cl).hasMatch())
    return QString("Pipe-to-shell pattern in command line");
  return {};
}

QString testRootFromUserPath(const ProcessInfo& p) {
  // On Windows we don't currently collect uid/sid, so this heuristic
  // is a no-op there — uid stays at -1 and we bail immediately.
  if (p.uid != 0)
    return {};
  if (p.exePath.isEmpty())
    return {};

  // Root processes that live in a user-writable path (~/, /tmp, /Volumes/USB,
  // etc.) are a strong privilege-escalation signal.
  const QString home = QDir::homePath();
  const bool inHome = !home.isEmpty() && p.exePath.startsWith(home + "/");
  if (inHome)
    return QString("Root process runs from user-writable path: %1").arg(p.exePath);

  if (p.exePath.startsWith("/tmp/") || p.exePath.startsWith("/var/tmp/") ||
      p.exePath.startsWith("/private/tmp/") || p.exePath.startsWith("/private/var/tmp/"))
    return QString("Root process runs from temp directory: %1").arg(p.exePath);

  return {};
}

// ----------------------------------------------------------------------------
// Top-level evaluator
// ----------------------------------------------------------------------------
QVector<SuspiciousProcess> evaluate(const QVector<ProcessInfo>& processes, bool checkSigning) {
  QVector<SuspiciousProcess> out;
  out.reserve(processes.size() / 8);  // typical ratio

  for (const ProcessInfo& p : processes) {
    if (p.isOurProcess)
      continue;  // never flag ourselves

    QStringList reasons;
    int score = 0;

    if (const QString r = testPath(p); !r.isEmpty()) {
      reasons.append(r);
      score += 40;
    }
    if (const QString r = testExeMissing(p); !r.isEmpty()) {
      reasons.append(r);
      score += 50;
    }
    if (const QString r = testRandomName(p); !r.isEmpty()) {
      reasons.append(r);
      score += 15;
    }
    if (const QString r = testCmdLine(p); !r.isEmpty()) {
      reasons.append(r);
      score += 30;
    }
    if (const QString r = testRootFromUserPath(p); !r.isEmpty()) {
      reasons.append(r);
      score += 40;
    }

    if (reasons.isEmpty())
      continue;

    // Don't flag based on RandomLookingName alone — too noisy.
    if (reasons.size() == 1 && reasons.first().contains("looks randomly generated"))
      continue;

    SuspiciousProcess sp;
    sp.info = p;
    sp.reasons = reasons;
    sp.score = std::min(100, score);

    // Optional: signature check (slow — guarded by checkSigning).
    if (checkSigning && !p.exePath.isEmpty()) {
      CodeSigning::Result cs = CodeSigning::verifyFile(p.exePath);
      sp.signingStatus = CodeSigning::statusToInt(cs.status);
      sp.signerId = cs.signerId;
      if (cs.status == CodeSigning::Status::Unsigned) {
        sp.reasons.append(QString("Executable is unsigned: %1").arg(p.exePath));
        sp.score = std::min(100, sp.score + 30);
      }
    }

    if (sp.score >= 60)
      sp.severity = "high";
    else if (sp.score >= 30)
      sp.severity = "medium";
    else
      sp.severity = "low";

    out.append(std::move(sp));
  }

  std::sort(out.begin(), out.end(), [](const SuspiciousProcess& a, const SuspiciousProcess& b) {
    return a.score > b.score;
  });
  return out;
}

}  // namespace SuspiciousHeuristics
