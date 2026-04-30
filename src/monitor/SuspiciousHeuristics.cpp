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
#include <QHash>
#include <QRegularExpression>
#include <QtGlobal>
#include <algorithm>

#include "reputation/CodeSigning.h"

namespace SuspiciousHeuristics {

// ============================================================================
// Developer-tool hidden-directory classifier.
//
// Why this exists:
//   The PathHidden heuristic flags any process whose exe path contains a
//   ".dotdir" segment. That correctly catches a dropper hiding in
//   ~/.cache/sus/x but also incorrectly catches normal developer tools
//   running out of:
//     • ~/.vscode/extensions/ms-vscode.cpptools-*/bin/cpptools-srv
//     • ~/.cursor/extensions/<ext>/bin/<binary>
//     • ~/.cargo/bin/<rust-binary>
//     • ~/.local/bin/<user-installed-tool>
//     • etc.
//
//   Real EDRs treat these as "review at most" because the *containing dir*
//   is a known managed location. We match the same way.
//
// Signature:
//   devToolLabelForSegment(seg) → human-readable tool name, or empty
//   if the segment is not a known dev-tool dotdir.
//
//   The caller iterates path segments and asks per-segment.
// ============================================================================
namespace {

QString devToolLabelForSegment(const QString& seg)
{
    // Exact-match dotdirs. Stable, unambiguous, lowercased.
    static const QHash<QString, QString> kExactDirs = {
        // ── Editors / IDEs ────────────────────────────────────────────
        { ".vscode",          QStringLiteral("VS Code")              },
        { ".vscode-server",   QStringLiteral("VS Code (remote)")     },
        { ".vscode-insiders", QStringLiteral("VS Code Insiders")     },
        { ".cursor",          QStringLiteral("Cursor")               },
        { ".cursor-server",   QStringLiteral("Cursor (remote)")      },
        { ".windsurf",        QStringLiteral("Windsurf")             },
        { ".atom",            QStringLiteral("Atom")                 },
        { ".brackets",        QStringLiteral("Brackets")             },

        // ── Language toolchains ───────────────────────────────────────
        { ".cargo",        QStringLiteral("Rust (cargo)")            },
        { ".rustup",       QStringLiteral("Rust (rustup)")           },
        { ".deno",         QStringLiteral("Deno")                    },
        { ".bun",          QStringLiteral("Bun")                     },
        { ".nvm",          QStringLiteral("Node.js (nvm)")           },
        { ".npm",          QStringLiteral("npm")                     },
        { ".npm-global",   QStringLiteral("npm (global)")            },
        { ".yarn",         QStringLiteral("Yarn")                    },
        { ".pnpm",         QStringLiteral("pnpm")                    },
        { ".pnpm-store",   QStringLiteral("pnpm (store)")            },
        { ".volta",        QStringLiteral("Volta")                   },
        { ".go",           QStringLiteral("Go")                      },
        { ".gopath",       QStringLiteral("Go (GOPATH)")             },
        { ".pyenv",        QStringLiteral("Python (pyenv)")          },
        { ".poetry",       QStringLiteral("Python (poetry)")         },
        { ".rbenv",        QStringLiteral("Ruby (rbenv)")            },
        { ".gem",          QStringLiteral("Ruby (gem)")              },
        { ".gradle",       QStringLiteral("Gradle")                  },
        { ".m2",           QStringLiteral("Maven")                   },
        { ".sdkman",       QStringLiteral("SDKMAN")                  },
        { ".dotnet",       QStringLiteral(".NET")                    },
        { ".nuget",        QStringLiteral(".NET (NuGet)")            },
        { ".platformio",   QStringLiteral("PlatformIO")              },

        // ── User-managed binary dirs ──────────────────────────────────
        // .local/bin is the XDG-spec location for user-installed CLIs.
        // Catching the parent .local works as long as the segment match
        // is by name; the actual binary lives in .local/bin or
        // .local/share/<app>/.
        { ".local",        QStringLiteral("User-local (.local/bin)") },

        // ── Containers / dev tooling ──────────────────────────────────
        { ".docker",       QStringLiteral("Docker")                  },
        { ".colima",       QStringLiteral("Colima")                  },
        { ".lima",         QStringLiteral("Lima")                    },
    };

    auto it = kExactDirs.constFind(seg);
    if (it != kExactDirs.constEnd())
        return it.value();

    // ── JetBrains IDEs use ".IntelliJIdea2024.1", ".WebStorm2024.3", etc.
    // Match by prefix; the version suffix changes every release.
    static const QStringList kJetBrainsPrefixes = {
        ".IntelliJIdea", ".WebStorm", ".PyCharm", ".PhpStorm",
        ".RubyMine",     ".CLion",     ".GoLand",  ".Rider",
        ".AndroidStudio", ".DataGrip", ".AppCode",
    };
    for (const QString& pfx : kJetBrainsPrefixes) {
        if (seg.startsWith(pfx))
            return QStringLiteral("JetBrains IDE");
    }

    return {};
}

// True when the reason returned by testPath() came from a dev-tool match.
// The evaluator uses this to weight the heuristic at 5 instead of 40.
bool isDevToolReason(const QString& reason)
{
    return reason.startsWith(QStringLiteral("Developer tool in hidden"));
}

}  // anonymous namespace

// ----------------------------------------------------------------------------
// Path-based heuristics
// ----------------------------------------------------------------------------
QString testPath(const ProcessInfo& p)
{
    const QString& path = p.exePath;
    if (path.isEmpty()) return {};

    // Lowercase + forward-slash normalization so the same heuristics work
    // against both Unix (/tmp/...) and Windows (C:\Users\...\Temp\...) paths.
    QString lower = path.toLower();
    lower.replace('\\', '/');

    // ── Temp / staging directories ─────────────────────────────────────
    // Unix
    if (lower.startsWith("/tmp/")
        || lower.startsWith("/var/tmp/")
        || lower.startsWith("/private/tmp/")
        || lower.startsWith("/private/var/tmp/"))
    {
        return QString("Executable runs from temp directory: %1").arg(path);
    }
    // Windows: %TEMP% lives under either the user's local AppData or
    // C:\Windows\Temp. Both are classic dropper staging areas.
    if (lower.contains("/appdata/local/temp/")
        || lower.contains("/windows/temp/"))
    {
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
    //
    // Dotdir segments are a real signal — droppers love hiding under
    // ~/.cache/x/ etc. — but they ALSO match every legitimate developer
    // tool: .vscode/extensions, .cargo/bin, .npm-global/bin, JetBrains
    // .IntelliJIdea2024.1, etc.
    //
    // Strategy:
    //   1. Walk the segments.
    //   2. If any segment matches a known dev-tool dotdir (devToolLabelForSegment),
    //      return a SOFT reason that the evaluator weights as Low/Info.
    //      Code-signing trust on top of that → suppressed entirely.
    //   3. Otherwise, the first hidden segment wins → Medium-severity reason.
    //
    // Truly suspicious files (like ~/.cache/.tmp/random_thing) still trip
    // the unlabelled rule and get the original 40-point weight.
    QString unknownHiddenSeg;
    for (const QString& seg : path.split('/', Qt::SkipEmptyParts)) {
        if (seg.size() <= 1 || !seg.startsWith('.') || seg == QStringLiteral(".."))
            continue;

        const QString devLabel = devToolLabelForSegment(seg);
        if (!devLabel.isEmpty()) {
            // Soft reason — recognised by the evaluator as a downgrade.
            return QString("Developer tool in hidden extension directory "
                           "— downgraded (%1, segment '%2')")
                       .arg(devLabel, seg);
        }

        // Remember the first unrecognised dotdir; only emit it as a
        // medium-severity reason if we don't find any dev-tool match
        // anywhere else on the path. (Most paths only have one dotdir
        // segment, but ~/.cache/.tool/.bin can have several — we want
        // the most-specific dev-tool match to win.)
        if (unknownHiddenSeg.isEmpty())
            unknownHiddenSeg = seg;
    }
    if (!unknownHiddenSeg.isEmpty())
        return QString("Executable lives under hidden directory '%1'")
                   .arg(unknownHiddenSeg);
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
        QStringList reasons;
        int  score    = 0;
        bool devToolPathOnly = false;   // tracked so signing-trust can suppress

        // testPath: a "Developer tool in hidden extension directory" reason
        // is a SOFT signal (weight 5) — well below the 30-point Medium
        // threshold, so on its own it surfaces as Low/Info. Any other
        // path reason (real /tmp, real /Downloads, real unknown dotdir)
        // keeps the original strong weight of 40.
        if (const QString r = testPath(p); !r.isEmpty()) {
            reasons.append(r);
            if (isDevToolReason(r)) {
                score += 5;             // Low / "needs review"
                devToolPathOnly = true; // may still be flipped off by other heuristics
            } else {
                score += 40;
            }
        }
        if (const QString r = testExeMissing(p); !r.isEmpty()) {
            reasons.append(r); score += 50; devToolPathOnly = false;
        }
        if (const QString r = testRandomName(p); !r.isEmpty()) {
            reasons.append(r); score += 15; devToolPathOnly = false;
        }
        if (const QString r = testCmdLine(p); !r.isEmpty()) {
            reasons.append(r); score += 30; devToolPathOnly = false;
        }
        if (const QString r = testRootFromUserPath(p); !r.isEmpty()) {
            reasons.append(r); score += 40; devToolPathOnly = false;
        }

        if (reasons.isEmpty()) continue;

        // Don't flag based on RandomLookingName alone — too noisy.
        if (reasons.size() == 1 && reasons.first().contains("looks randomly generated"))
            continue;

        SuspiciousProcess sp;
        sp.info    = p;
        sp.reasons = reasons;
        sp.score   = std::min(100, score);

        // Optional: signature check (slow — guarded by checkSigning).
        // Two contracts here:
        //   (a) Unsigned + bad path → bump score by 30 (existing behavior).
        //   (b) Phase-5 follow-up: when the ONLY reason is a dev-tool path
        //       AND the binary is SignedTrusted (or package-managed on
        //       Linux via the SignedUntrusted system-path heuristic),
        //       suppress the alert entirely. This is what fixes the
        //       cpptools-srv / pet false positives reported in the demo.
        if (checkSigning && !p.exePath.isEmpty()) {
            CodeSigning::Result cs = CodeSigning::verifyFile(p.exePath);
            sp.signingStatus = CodeSigning::statusToInt(cs.status);
            sp.signerId      = cs.signerId;

            const bool trustSignal =
                  cs.status == CodeSigning::Status::SignedTrusted
               || cs.status == CodeSigning::Status::SignedUntrusted;

            if (devToolPathOnly && trustSignal) {
                // Suppressed — legitimate dev tool, signed/package-managed.
                // Skipping `out.append` is the suppression.
                continue;
            }

            if (cs.status == CodeSigning::Status::Unsigned && !devToolPathOnly) {
                // Unsigned-and-bad-path bump only applies for paths the
                // user has NOT classified as a dev-tool extension dir.
                // Skipping the bump for dev-tool paths is what keeps a
                // Linux VS Code binary (unsigned, no dpkg ownership)
                // at Low/Info severity instead of being kicked into
                // Medium by the +30 penalty.
                sp.reasons.append(QString("Executable is unsigned: %1").arg(p.exePath));
                sp.score = std::min(100, sp.score + 30);
            }
        }

        // Severity ladder — score → label.
        // Below 10 = "info" (dev-tool path with no other signal). The
        // existing UI maps "info" through processSeverity() → Severity::Low
        // (which is what we want; Severity::Info exists in EDR but the
        // process-flow rolls Info into Low for now).
        if      (sp.score >= 60) sp.severity = QStringLiteral("high");
        else if (sp.score >= 30) sp.severity = QStringLiteral("medium");
        else if (sp.score >= 10) sp.severity = QStringLiteral("low");
        else                      sp.severity = QStringLiteral("info");

        out.append(std::move(sp));
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
