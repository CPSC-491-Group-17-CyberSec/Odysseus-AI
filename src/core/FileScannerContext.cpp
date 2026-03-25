// FileScannerContext.cpp
// OS / filesystem detection and filter-list construction.
// Run once at scan startup – not performance-critical.

#include "FileScanner.h"

#include <QStorageInfo>

// ============================================================================
// detectContext
// ============================================================================
ScanContext FileScannerWorker::detectContext(const QString& rootPath)
{
    ScanContext ctx;

#if defined(Q_OS_LINUX)
    ctx.runningOnLinux   = true;
#elif defined(Q_OS_WIN)
    ctx.runningOnWindows = true;
#elif defined(Q_OS_MACOS)
    ctx.runningOnMac     = true;
#endif

    QStorageInfo si(rootPath);
    si.refresh();
    ctx.fsType     = QString::fromUtf8(si.fileSystemType()).toLower();
    ctx.isReadOnly = si.isReadOnly();

    static const QVector<QString> windowsFsTypes = {
        "ntfs", "fat", "fat32", "vfat", "exfat", "refs", "fuseblk"
    };
    static const QVector<QString> linuxFsTypes = {
        "ext2", "ext3", "ext4", "btrfs", "xfs", "zfs", "f2fs",
        "reiserfs", "nilfs2", "tmpfs", "overlayfs", "squashfs",
        "aufs", "erofs", "bcachefs"
    };
    static const QVector<QString> macFsTypes   = { "apfs", "hfs", "hfsplus" };
    static const QVector<QString> networkFsTypes = {
        "nfs", "nfs4", "cifs", "smb", "smb2", "smbfs",
        "fuse.sshfs", "fuse.gvfsd-fuse", "davfs2", "9p", "virtiofs"
    };

    ctx.isWindowsFs = windowsFsTypes.contains(ctx.fsType);
    ctx.isLinuxFs   = linuxFsTypes.contains(ctx.fsType);
    ctx.isMacFs     = macFsTypes.contains(ctx.fsType);
    ctx.isNetworkFs = networkFsTypes.contains(ctx.fsType) || ctx.fsType.startsWith("fuse.");
    ctx.isRemovable = (ctx.fsType == "vfat" || ctx.fsType == "fat" ||
                       ctx.fsType == "fat32" || ctx.fsType == "exfat");

    if (!ctx.isWindowsFs && !ctx.isLinuxFs && !ctx.isMacFs && !ctx.isNetworkFs) {
        if      (ctx.runningOnWindows) ctx.isWindowsFs = true;
        else if (ctx.runningOnMac)     ctx.isMacFs     = true;
        else                            ctx.isLinuxFs   = true;
    }

    return ctx;
}

// ============================================================================
// buildFilterLists
// Only two lists remain:
//   m_skipDirFragments  – directories to skip for performance (virtual FS,
//                         package-manager caches, recycle bins, etc.)
//   m_noHashExtensions  – file types whose hashes will never appear in any
//                         malware database, so we skip the SHA-256 I/O entirely.
// ============================================================================
void FileScannerWorker::buildFilterLists()
{
    const bool linCtx = m_ctx.isLinuxFs   || m_ctx.runningOnLinux;
    const bool macCtx = m_ctx.isMacFs     || m_ctx.runningOnMac;
    const bool winCtx = m_ctx.isWindowsFs || m_ctx.isRemovable || m_ctx.runningOnWindows;

    // ---- Directories to skip entirely (never contain real files worth hashing)
    m_skipDirFragments = {
        "/node_modules/",
        "/.git/",
        "/.local/share/trash",
        "/.trash"
    };

    if (linCtx) {
        m_skipDirFragments.append({
            "/proc/", "/sys/", "/dev/", "/run/",
            "/steamrt", "/steam-runtime",
            "/steamlinuxruntime",
            "/pressure-vessel", "/pv-runtime",
            "/.cache/pip", "/.cache/yarn",
            "/.cache/npm", "/.cache/cargo",
            "/go/pkg/mod/cache"
        });
    }
    if (macCtx) {
        m_skipDirFragments.append({
            "/system/library/caches", "/private/var/vm",
            "/.spotlight-v100", "/.fseventsd", "/.mobilebackups"
        });
    }
    if (winCtx) {
        m_skipDirFragments.append({
            "\\windows\\winsxs", "\\windows\\installer",
            "\\windows\\softwaredistribution",
            "\\$recycle.bin", "\\system volume information"
        });
    }

    // ---- Extensions exempt from SHA-256 hashing
    // These types will never appear in a malware hash database and are too
    // numerous to hash without adding significant I/O overhead.
    m_noHashExtensions = {
        "so", "ko", "o", "a", "pyc", "pyo",
        "ttf", "otf", "woff", "woff2",
        "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp",
        "mp3", "wav", "flac", "ogg",
        "mp4", "avi", "mkv", "mov", "webm",
        "db", "sqlite", "sqlite3",
        "log"
    };
}

// ============================================================================
// FileScannerWorker – constructor
// ============================================================================
FileScannerWorker::FileScannerWorker(const QString& rootPath,
                                     QAtomicInt*    cancelFlag,
                                     QObject*       parent)
    : QObject(parent)
    , m_rootPath(rootPath)
    , m_cancelFlag(cancelFlag)
{
    m_ctx    = detectContext(rootPath);
    buildFilterLists();
    m_hashDb = loadHashDatabase();
}
