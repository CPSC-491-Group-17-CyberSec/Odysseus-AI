// ============================================================================
// ProcessEnumerator.cpp  –  macOS sysctl + Linux /proc process listing
//
// Structure (cross-platform stabilization pass):
//   • ONE `namespace ProcessEnumerator { ... }` wraps the whole file.
//   • Platform-specific includes are at file scope, guarded by Q_OS_*
//     so non-Unix builds (Windows) don't try to pull pwd.h / unistd.h.
//   • Each public function (`list`, `resolveUser`) is defined exactly
//     once; the body switches on the platform with `#if/#elif/#else`
//     INSIDE the function — never around the namespace itself. This is
//     what fixes the previous bug where the file had unbalanced
//     namespace braces on Linux.
//
// macOS notes (Apple Silicon M4 verified):
//   • sysctl(KERN_PROC_ALL) returns an array of `kinfo_proc`. Field layout
//     is the same on x86_64 and arm64.
//   • proc_pidpath() lives in <libproc.h>; statically linked into libSystem,
//     no separate library required.
//   • KERN_PROCARGS2 returns a packed buffer: [argc:i32][exec_path][padding]
//     [argv0\0argv1\0...][envp...]. Bouncing through this buffer is the
//     only way to get the full argv on macOS without a kernel ext.
//   • EPERM on KERN_PROCARGS2 is NORMAL for processes belonging to other
//     users / sandboxed apps without Full Disk Access. We mark cmdLine as
//     "(restricted)" and bump restrictedCount instead of erroring out.
//
// Linux notes (verified Ubuntu 22.04 / Debian 12):
//   • /proc is the source of truth. /proc/<pid>/exe is a symlink — readlink
//     it; if the target ends in " (deleted)" the binary has been unlinked
//     while the process kept running (a classic dropper / in-memory pattern).
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

#include <cerrno>
#include <cstring>
#include <vector>

// ── POSIX headers (macOS + Linux) ──────────────────────────────────────────
// Wrapped so a future Windows build can compile cleanly with a different
// resolveUser() / pid-listing strategy.
#if defined(Q_OS_MACOS) || defined(Q_OS_LINUX) || defined(Q_OS_UNIX)
#  include <pwd.h>
#  include <unistd.h>
#  include <sys/types.h>
#endif

// ── macOS-only headers ─────────────────────────────────────────────────────
#if defined(Q_OS_MACOS)
#  include <sys/sysctl.h>
#  include <libproc.h>
#  include <sys/proc_info.h>
#endif

// ── Windows-only headers ───────────────────────────────────────────────────
#if defined(Q_OS_WIN)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <tlhelp32.h>
#  include <psapi.h>
#endif

// ============================================================================
// Single namespace block — everything below lives inside ProcessEnumerator.
// ============================================================================
namespace ProcessEnumerator {

// ----------------------------------------------------------------------------
// resolveUser  –  cross-platform; uses getpwuid_r where available.
// ----------------------------------------------------------------------------
QString resolveUser(int uid)
{
    if (uid < 0) return QStringLiteral("uid:?");

#if defined(Q_OS_MACOS) || defined(Q_OS_LINUX) || defined(Q_OS_UNIX)
    char           buf[2048];
    struct passwd  pwd;
    struct passwd* result = nullptr;
    const int rc = ::getpwuid_r(static_cast<uid_t>(uid),
                                 &pwd, buf, sizeof(buf), &result);
    if (rc == 0 && result && result->pw_name)
        return QString::fromUtf8(result->pw_name);
    return QString("uid:%1").arg(uid);
#else
    // Windows / other: no POSIX passwd database. Fall back to numeric uid.
    return QString("uid:%1").arg(uid);
#endif
}

// ============================================================================
// macOS: helper to read /argv via KERN_PROCARGS2
// (Defined here so list() below can call it from inside the same #if block.)
// ============================================================================
#if defined(Q_OS_MACOS)

// Returns:
//   1  → ok, cmdLine populated
//   0  → no args (kernel threads, very early init)
//  -1  → EPERM / access denied (caller marks "(restricted)" and continues)
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
        return -1;   // EINVAL / EPERM / ESRCH — all map to "skip this pid"
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
        while (p < end && *p == '\0') ++p;   // advance past terminator
    }
    outCmdLine = args.join(' ');
    return 1;
}

#endif   // Q_OS_MACOS — readCmdLine

// ============================================================================
// Linux: helper to slurp small /proc files
// ============================================================================
#if defined(Q_OS_LINUX)

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

#endif   // Q_OS_LINUX — /proc helpers

// ============================================================================
// list  –  one definition; body switches on the platform.
// ============================================================================
bool list(QVector<ProcessInfo>& out, int& restrictedCount)
{
    restrictedCount = 0;

#if defined(Q_OS_MACOS)
    // ── macOS path: sysctl(KERN_PROC_ALL) + libproc ────────────────────
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

        if (!info.exePath.isEmpty() && !QFile::exists(info.exePath))
            info.exeMissing = true;

        out.append(std::move(info));
    }
    return true;

#elif defined(Q_OS_LINUX)
    // ── Linux path: /proc walking ──────────────────────────────────────
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

        // /proc/<pid>/comm — short name (kernel-truncated to 16 chars)
        info.name = readSmallFile(base + "/comm").trimmed();
        if (info.name.isEmpty()) {
            // Process vanished between readdir and open — skip silently.
            continue;
        }

        // /proc/<pid>/status — Uid + PPid
        const QString status = readSmallFile(base + "/status");
        info.uid  = parseUidFromStatus(status);
        info.ppid = parsePpidFromStatus(status);
        info.user = resolveUser(info.uid);

        // /proc/<pid>/exe — symlink to executable; may end in " (deleted)"
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

        // /proc/<pid>/cmdline — null-separated argv
        QFile cmdF(base + "/cmdline");
        if (cmdF.open(QIODevice::ReadOnly)) {
            QByteArray raw = cmdF.readAll();
            cmdF.close();
            for (auto& c : raw) if (c == '\0') c = ' ';
            info.cmdLine = QString::fromUtf8(raw).trimmed();
        }
        if (info.cmdLine.isEmpty() && info.exePath.isEmpty()) {
            // Kernel thread or restricted.
            info.cmdLine = QStringLiteral("(restricted)");
            ++restrictedCount;
        }

        out.append(std::move(info));
    }
    return true;

#elif defined(Q_OS_WIN)
    // ── Windows path: Toolhelp32 snapshot ──────────────────────────────
    // We pick Toolhelp over the WTS API because it's reachable without
    // privilege and produces a stable PID/PPID/Name set across Windows
    // 10 / 11. For each PID we then try OpenProcess at the lowest
    // privilege level (PROCESS_QUERY_LIMITED_INFORMATION, available since
    // Windows Vista) and call QueryFullProcessImageNameW for the path.
    // EACCES/ERROR_ACCESS_DENIED on protected processes (System, csrss,
    // smss, etc.) is normal — we mark them restricted and continue.
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        qWarning() << "[SysMon] CreateToolhelp32Snapshot failed:"
                   << ::GetLastError();
        return false;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (!::Process32FirstW(snap, &pe)) {
        ::CloseHandle(snap);
        qWarning() << "[SysMon] Process32FirstW failed:" << ::GetLastError();
        return false;
    }

    const int selfPid = static_cast<int>(::GetCurrentProcessId());
    do {
        if (pe.th32ProcessID == 0) continue;     // skip System Idle Process

        ProcessInfo info;
        info.pid          = static_cast<int>(pe.th32ProcessID);
        info.ppid         = static_cast<int>(pe.th32ParentProcessID);
        info.uid          = -1;
        info.name         = QString::fromWCharArray(pe.szExeFile);
        info.user         = QStringLiteral("unknown");   // see resolveUser stub below
        info.isOurProcess = (info.pid == selfPid);

        // Try to upgrade name → full path using QueryFullProcessImageNameW.
        HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                  FALSE, pe.th32ProcessID);
        if (h) {
            wchar_t pathBuf[MAX_PATH] = {0};
            DWORD pathLen = MAX_PATH;
            if (::QueryFullProcessImageNameW(h, 0, pathBuf, &pathLen)) {
                info.exePath = QString::fromWCharArray(pathBuf, pathLen);
            }
            ::CloseHandle(h);
        }

        if (info.exePath.isEmpty()) {
            // Permission denied — flag as restricted and continue.
            info.cmdLine = QStringLiteral("(restricted)");
            ++restrictedCount;
        } else if (!QFile::exists(info.exePath)) {
            info.exeMissing = true;
        }

        // We deliberately do NOT collect command line on Windows in this
        // pass. NtQueryInformationProcess + ProcessParameters works but
        // is complex and prone to anti-cheat / EDR conflicts. Phase 4
        // material if we ever need it.

        out.append(std::move(info));
    } while (::Process32NextW(snap, &pe));

    ::CloseHandle(snap);
    return true;

#else
    // ── Unsupported platform ───────────────────────────────────────────
    Q_UNUSED(out)
    qInfo() << "[SysMon] process enumeration not implemented on this platform";
    return false;
#endif
}

}  // namespace ProcessEnumerator   ← single close, after #endif of any platform block
