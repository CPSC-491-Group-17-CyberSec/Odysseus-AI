// ============================================================================
// ProcessEnumerator.cpp  –  macOS sysctl + Linux /proc process listing
//
// Implementation pattern matches CodeSigning.cpp / FileScannerContext.cpp:
// platform-specific code is gated by Q_OS_* macros, with a polite stub for
// any other OS so the build never breaks.
//
// macOS notes (Apple Silicon M4 verified):
//   • sysctl(KERN_PROC_ALL) returns an array of `kinfo_proc`. Field layout
//     is the same on x86_64 and arm64.
//   • proc_pidpath() lives in <libproc.h>; statically linked into libSystem,
//     no separate library required.
//   • KERN_PROCARGS2 returns a packed buffer: [argc:i32][exec_path][padding]
//     [argv0\0argv1\0...][envp...]. Bouncing through this buffer is the only
//     way to get the full argv on macOS without a kernel ext.
//   • EPERM on KERN_PROCARGS2 is NORMAL for processes belonging to other
//     users / sandboxed apps without Full Disk Access. We mark cmdLine as
//     "(restricted)" and bump restrictedCount instead of erroring out.
//
// Linux notes:
//   • /proc is the source of truth. /proc/<pid>/exe is a symlink — readlink
//     it; if the target ends in " (deleted)" the binary has been unlinked
//     while the process kept running (a classic dropper/in-memory pattern).
//   • /proc/<pid>/cmdline is null-separated; we replace \0 with space.
//   • Some pids are inaccessible (EACCES) without root. We skip those rather
//     than failing the whole listing.
// ============================================================================

#include "monitor/ProcessEnumerator.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QDebug>
#include <QtGlobal>

// Platform-specific syscalls. Pulling these in at the top of the TU (rather
// than inside the namespace) keeps the C/POSIX headers in their natural
// global scope — they don't play well with being parsed inside a C++
// namespace.
#include <pwd.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <vector>

#if defined(Q_OS_MACOS)
#  include <sys/sysctl.h>
#  include <libproc.h>
#  include <sys/proc_info.h>
#endif

namespace ProcessEnumerator {

// ----------------------------------------------------------------------------
// resolveUser  –  cross-platform; uses getpwuid_r where available
// ----------------------------------------------------------------------------
QString resolveUser(int uid)
{
    if (uid < 0) return QStringLiteral("uid:?");

    char buf[2048];
    struct passwd  pwd;
    struct passwd* result = nullptr;

    const int rc = ::getpwuid_r(static_cast<uid_t>(uid),
                                 &pwd, buf, sizeof(buf), &result);
    if (rc == 0 && result && result->pw_name)
        return QString::fromUtf8(result->pw_name);
    return QString("uid:%1").arg(uid);
}

// ============================================================================
// macOS implementation
// ============================================================================
#if defined(Q_OS_MACOS)

// Read the full argv of a single PID via KERN_PROCARGS2.
// Returns:
//   1  → ok, cmdLine populated
//   0  → no args (kernel threads, very early init)
//  -1  → EPERM / access denied (caller should mark "(restricted)" and continue)
static int readCmdLine(int pid, QString& outExePath, QString& outCmdLine)
{
    int    argMax = 0;
    size_t sz     = sizeof(argMax);
    {
        int mib[2] = { CTL_KERN, KERN_ARGMAX };
        if (::sysctl(mib, 2, &argMax, &sz, nullptr, 0) != 0)
            argMax = 4096;
    }
    if (argMax <= 0) argMax = 4096;

    std::vector<char> buf(static_cast<size_t>(argMax));
    int    mib[3] = { CTL_KERN, KERN_PROCARGS2, pid };
    size_t bufLen = buf.size();
    if (::sysctl(mib, 3, buf.data(), &bufLen, nullptr, 0) != 0) {
        return (errno == EINVAL || errno == EPERM || errno == ESRCH) ? -1 : -1;
    }
    if (bufLen < sizeof(int)) return 0;

    // Layout: argc (int) | exec_path\0 | padding(\0...) | argv0\0argv1\0...
    int argc = 0;
    std::memcpy(&argc, buf.data(), sizeof(int));

    const char* p   = buf.data() + sizeof(int);
    const char* end = buf.data() + bufLen;

    if (p < end && *p) {
        outExePath = QString::fromUtf8(p);
        p += std::strlen(p);
    }
    while (p < end && *p == '\0') ++p;   // skip pad

    QStringList args;
    for (int i = 0; i < argc && p < end; ++i) {
        const QString a = QString::fromUtf8(p);
        args.append(a);
        p += a.toUtf8().size();
        // advance past the \0 terminator
        while (p < end && *p == '\0') ++p;
    }
    outCmdLine = args.join(' ');
    return 1;
}

bool list(QVector<ProcessInfo>& out, int& restrictedCount)
{
    restrictedCount = 0;

    int    mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    size_t sz     = 0;

    if (::sysctl(mib, 3, nullptr, &sz, nullptr, 0) != 0) {
        qWarning() << "[SysMon] sysctl(KERN_PROC_ALL) sizing failed:"
                   << std::strerror(errno);
        return false;
    }

    // Add slack — process count can grow between the sizing call and the read.
    sz += 64 * sizeof(struct kinfo_proc);
    std::vector<char> raw(sz);
    if (::sysctl(mib, 3, raw.data(), &sz, nullptr, 0) != 0) {
        qWarning() << "[SysMon] sysctl(KERN_PROC_ALL) read failed:"
                   << std::strerror(errno);
        return false;
    }

    const auto* procs = reinterpret_cast<struct kinfo_proc*>(raw.data());
    const int   n     = static_cast<int>(sz / sizeof(struct kinfo_proc));
    const int   selfPid = ::getpid();

    out.reserve(out.size() + n);
    for (int i = 0; i < n; ++i) {
        const struct kinfo_proc& kp = procs[i];
        if (kp.kp_proc.p_pid == 0) continue;  // skip kernel_task pid 0

        ProcessInfo info;
        info.pid           = kp.kp_proc.p_pid;
        info.ppid          = kp.kp_eproc.e_ppid;
        info.uid           = static_cast<int>(kp.kp_eproc.e_ucred.cr_uid);
        info.name          = QString::fromUtf8(kp.kp_proc.p_comm);
        info.user          = resolveUser(info.uid);
        info.isOurProcess  = (info.pid == selfPid);

        // Full executable path
        char pathBuf[PROC_PIDPATHINFO_MAXSIZE] = {0};
        if (proc_pidpath(info.pid, pathBuf, sizeof(pathBuf)) > 0)
            info.exePath = QString::fromUtf8(pathBuf);

        // Command line via KERN_PROCARGS2
        QString exePathFromArgs;
        const int rc = readCmdLine(info.pid, exePathFromArgs, info.cmdLine);
        if (rc < 0) {
            info.cmdLine = QStringLiteral("(restricted)");
            ++restrictedCount;
        } else if (info.exePath.isEmpty() && !exePathFromArgs.isEmpty()) {
            info.exePath = exePathFromArgs;
        }

        // Did the executable get unlinked while running?
        if (!info.exePath.isEmpty() && !QFile::exists(info.exePath))
            info.exeMissing = true;

        out.append(std::move(info));
    }
    return true;
}

}  // namespace ProcessEnumerator

// ============================================================================
// Linux implementation
// ============================================================================
#elif defined(Q_OS_LINUX)

namespace ProcessEnumerator {

static QString readSmallFile(const QString& path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};
    const QByteArray data = f.readAll();
    f.close();
    return QString::fromUtf8(data);
}

static int parseUidFromStatus(const QString& statusText)
{
    // /proc/<pid>/status line:  "Uid:\t<real>\t<eff>\t<saved>\t<fs>"
    for (const QString& line : statusText.split('\n')) {
        if (!line.startsWith("Uid:")) continue;
        const QStringList parts = line.split(QRegularExpression("\\s+"),
                                              Qt::SkipEmptyParts);
        if (parts.size() >= 2) {
            bool ok = false;
            const int uid = parts[1].toInt(&ok);
            if (ok) return uid;
        }
        break;
    }
    return -1;
}

static int parsePpidFromStatus(const QString& statusText)
{
    for (const QString& line : statusText.split('\n')) {
        if (!line.startsWith("PPid:")) continue;
        const QStringList parts = line.split(QRegularExpression("\\s+"),
                                              Qt::SkipEmptyParts);
        if (parts.size() >= 2) {
            bool ok = false;
            const int ppid = parts[1].toInt(&ok);
            if (ok) return ppid;
        }
        break;
    }
    return 0;
}

bool list(QVector<ProcessInfo>& out, int& restrictedCount)
{
    restrictedCount = 0;

    QDir proc("/proc");
    if (!proc.exists()) {
        qWarning() << "[SysMon] /proc not present — cannot enumerate processes";
        return false;
    }

    const int selfPid = static_cast<int>(::getpid());
    const QStringList entries = proc.entryList(QDir::Dirs | QDir::NoDotAndDotDot,
                                                QDir::NoSort);

    for (const QString& e : entries) {
        bool isPid = false;
        const int pid = e.toInt(&isPid);
        if (!isPid || pid <= 0) continue;

        const QString base = QString("/proc/%1").arg(pid);

        ProcessInfo info;
        info.pid          = pid;
        info.isOurProcess = (pid == selfPid);

        // /proc/<pid>/comm – short name (kernel-truncated to 16 chars)
        info.name = readSmallFile(base + "/comm").trimmed();
        if (info.name.isEmpty()) {
            // Process vanished between readdir and open — skip silently.
            continue;
        }

        // /proc/<pid>/status – Uid + PPid
        const QString status = readSmallFile(base + "/status");
        info.uid  = parseUidFromStatus(status);
        info.ppid = parsePpidFromStatus(status);
        info.user = resolveUser(info.uid);

        // /proc/<pid>/exe – symlink to executable; may end in " (deleted)"
        char linkBuf[4096] = {0};
        const ssize_t got = ::readlink(QFile::encodeName(base + "/exe").constData(),
                                        linkBuf, sizeof(linkBuf) - 1);
        if (got > 0) {
            linkBuf[got] = 0;
            info.exePath = QString::fromUtf8(linkBuf);
            if (info.exePath.endsWith(" (deleted)")) {
                info.exeMissing = true;
                info.exePath.chop(QString(" (deleted)").size());
            } else if (!QFile::exists(info.exePath)) {
                info.exeMissing = true;
            }
        } else {
            ++restrictedCount;
        }

        // /proc/<pid>/cmdline – null-separated argv
        QFile cmdF(base + "/cmdline");
        if (cmdF.open(QIODevice::ReadOnly)) {
            QByteArray raw = cmdF.readAll();
            cmdF.close();
            for (auto& c : raw) if (c == '\0') c = ' ';
            info.cmdLine = QString::fromUtf8(raw).trimmed();
        }
        if (info.cmdLine.isEmpty() && info.exePath.isEmpty()) {
            // Couldn't read either — kernel thread or restricted.
            info.cmdLine = QStringLiteral("(restricted)");
            ++restrictedCount;
        }

        out.append(std::move(info));
    }
    return true;
}

}  // namespace ProcessEnumerator

// ============================================================================
// Stub for unsupported platforms
// ============================================================================
#else

namespace ProcessEnumerator {

bool list(QVector<ProcessInfo>& /*out*/, int& restrictedCount)
{
    restrictedCount = 0;
    qInfo() << "[SysMon] process enumeration not implemented on this platform";
    return false;
}

}  // namespace ProcessEnumerator

#endif
