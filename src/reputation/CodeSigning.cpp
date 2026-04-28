// ============================================================================
// CodeSigning.cpp  –  signature verification, user-space only
//
// Implementation strategy: shell out via QProcess. We could link against
// macOS's <Security/SecCode.h> for in-process validation, but that pulls in
// the Security framework + a forest of CF types that don't play nicely with
// Qt's MOC. The codesign(1) binary is part of the OS and is never missing
// on a developer machine.
//
// All commands run with a 5-second timeout. If the OS tool hangs (very rare
// but has happened on corrupt files), we kill and return Unknown.
// ============================================================================

#include "reputation/CodeSigning.h"

#include <QProcess>
#include <QFileInfo>
#include <QRegularExpression>
#include <QDebug>

namespace CodeSigning {

QString statusToText(Status s)
{
    switch (s) {
        case Status::SignedTrusted:    return "signed (trusted)";
        case Status::SignedUntrusted:  return "signed (untrusted)";
        case Status::Unsigned:         return "unsigned";
        default:                       return "unknown";
    }
}

namespace {

// ----------------------------------------------------------------------------
// runTool  –  helper that runs a CLI tool and returns its (stdout, stderr).
// 5-second timeout; empty result on timeout or launch failure.
// ----------------------------------------------------------------------------
struct ToolResult {
    int     exitCode = -1;
    QString stdoutText;
    QString stderrText;
    bool    timedOut = false;
};

ToolResult runTool(const QString& program, const QStringList& args)
{
    ToolResult r;
    QProcess p;
    p.start(program, args);
    if (!p.waitForStarted(1500)) return r;
    if (!p.waitForFinished(5000)) {
        p.kill();
        p.waitForFinished(500);
        r.timedOut = true;
        return r;
    }
    r.exitCode    = p.exitCode();
    r.stdoutText  = QString::fromUtf8(p.readAllStandardOutput());
    r.stderrText  = QString::fromUtf8(p.readAllStandardError());
    return r;
}

}  // anonymous namespace

// ============================================================================
// macOS implementation
// ============================================================================
#if defined(Q_OS_MACOS)

Result verifyFile(const QString& filePath)
{
    Result out;

    // codesign expects the bundle root for .app, but works on plain Mach-O
    // binaries too. We pass the path as-is — the user is welcome to point
    // at /Applications/Foo.app/Contents/MacOS/Foo if they want.
    const ToolResult t = runTool("/usr/bin/codesign",
                                  { "-dv", "--verbose=2", filePath });

    // codesign writes its info to STDERR; STDOUT is usually empty.
    const QString combined = t.stderrText + t.stdoutText;
    out.rawDetails = combined.left(512);

    if (t.timedOut) {
        out.status = Status::Unknown;
        return out;
    }

    // Common phrases:
    //   "code object is not signed at all"
    //   "Authority=Developer ID Application: <Org> (<TEAMID>)"
    //   "TeamIdentifier=ABCDE12345"
    if (combined.contains("not signed at all", Qt::CaseInsensitive)) {
        out.status = Status::Unsigned;
        return out;
    }

    // Pull the FIRST Authority= line — it's the signing identity.
    QRegularExpression authRx(R"(^Authority=(.+)$)",
                              QRegularExpression::MultilineOption);
    QRegularExpressionMatch authM = authRx.match(combined);
    if (authM.hasMatch())
        out.signerId = authM.captured(1).trimmed();

    QRegularExpression teamRx(R"(^TeamIdentifier=([A-Z0-9]+)$)",
                              QRegularExpression::MultilineOption);
    QRegularExpressionMatch teamM = teamRx.match(combined);
    if (teamM.hasMatch()) {
        if (!out.signerId.isEmpty())
            out.signerId += QString(" [TeamID:%1]").arg(teamM.captured(1));
        else
            out.signerId = QString("TeamID:%1").arg(teamM.captured(1));
    }

    if (!out.signerId.isEmpty()) {
        // We have a signer. Decide trusted vs untrusted.
        // Trusted authorities on macOS for distribution:
        //   Apple Mac OS Application Signing
        //   Software Signing
        //   Apple Code Signing Certification Authority
        //   Developer ID Application: <Org>
        //   Apple Mac OS Application Signing
        const bool isApple = out.signerId.contains("Apple", Qt::CaseInsensitive)
                          || out.signerId.contains("Developer ID", Qt::CaseInsensitive)
                          || out.signerId.contains("Software Signing", Qt::CaseInsensitive);
        out.status = isApple ? Status::SignedTrusted : Status::SignedUntrusted;
        return out;
    }

    // No Authority line and not "not signed". Fall back to exit code:
    //   exit 0 with no Authority is unusual — treat as unknown.
    out.status = Status::Unknown;
    return out;
}

// ============================================================================
// Linux implementation
// ============================================================================
#elif defined(Q_OS_LINUX)

namespace {
bool checkDpkgOwnership(const QString& filePath, QString& outPackage)
{
    const ToolResult t = runTool("dpkg", { "-S", filePath });
    if (t.exitCode == 0 && !t.stdoutText.trimmed().isEmpty()) {
        // Output format:  "<package>: <path>"
        const int colon = t.stdoutText.indexOf(':');
        outPackage = (colon > 0 ? t.stdoutText.left(colon) : t.stdoutText).trimmed();
        return true;
    }
    return false;
}

bool checkRpmOwnership(const QString& filePath, QString& outPackage)
{
    const ToolResult t = runTool("rpm", { "-qf", filePath });
    if (t.exitCode == 0
        && !t.stdoutText.contains("not owned", Qt::CaseInsensitive))
    {
        outPackage = t.stdoutText.trimmed();
        return !outPackage.isEmpty();
    }
    return false;
}
}  // anonymous

Result verifyFile(const QString& filePath)
{
    Result out;
    QString pkg;

    if (checkDpkgOwnership(filePath, pkg)) {
        out.status     = Status::SignedTrusted;     // package-owned = trusted
        out.signerId   = QString("dpkg:%1").arg(pkg);
        out.rawDetails = "Owned by dpkg package " + pkg;
        return out;
    }
    if (checkRpmOwnership(filePath, pkg)) {
        out.status     = Status::SignedTrusted;
        out.signerId   = QString("rpm:%1").arg(pkg);
        out.rawDetails = "Owned by rpm package " + pkg;
        return out;
    }

    // Not owned by a package manager. On Linux this is normal for user
    // binaries (~/bin, ~/.local/bin). We don't have a strong signal —
    // mark Unsigned rather than Unknown so the UI can render something.
    out.status     = Status::Unsigned;
    out.rawDetails = "No package manager owner found";
    return out;
}

// ============================================================================
// Other platforms (Windows, etc.) – stub
// ============================================================================
#else

Result verifyFile(const QString& /*filePath*/)
{
    Result out;
    out.status     = Status::Unknown;
    out.rawDetails = "code signing check not implemented on this platform";
    return out;
}

#endif

}  // namespace CodeSigning
