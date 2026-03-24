#include "FileScanner.h"

#include <QDirIterator>
#include <QFileInfo>
#include <QFile>
#include <QDir>
#include <QElapsedTimer>
#include <QThread>
#include <QRegularExpression>
#include <QStorageInfo>

// ============================================================================
// detectContext  –  static, called before filter lists are built
// ============================================================================
// static
ScanContext FileScannerWorker::detectContext(const QString& rootPath)
{
    ScanContext ctx;

    // -- Compile-time OS detection --
#if defined(Q_OS_LINUX)
    ctx.runningOnLinux   = true;
#elif defined(Q_OS_WIN)
    ctx.runningOnWindows = true;
#elif defined(Q_OS_MACOS)
    ctx.runningOnMac     = true;
#endif

    // -- Runtime filesystem detection --
    QStorageInfo si(rootPath);
    si.refresh();
    ctx.fsType     = QString::fromUtf8(si.fileSystemType()).toLower();
    ctx.isReadOnly = si.isReadOnly();

    // Windows-native formats.
    // "fuseblk" is used by ntfs-3g on Linux when mounting NTFS drives.
    static const QVector<QString> windowsFsTypes = {
        "ntfs", "fat", "fat32", "vfat", "exfat", "refs", "fuseblk"
    };
    // Linux-native formats
    static const QVector<QString> linuxFsTypes = {
        "ext2", "ext3", "ext4", "btrfs", "xfs", "zfs", "f2fs",
        "reiserfs", "nilfs2", "tmpfs", "overlayfs", "squashfs",
        "aufs", "erofs", "bcachefs"
    };
    // macOS formats
    static const QVector<QString> macFsTypes = {
        "apfs", "hfs", "hfsplus"
    };
    // Network / FUSE pseudo-filesystems
    static const QVector<QString> networkFsTypes = {
        "nfs", "nfs4", "cifs", "smb", "smb2", "smbfs",
        "fuse.sshfs", "fuse.gvfsd-fuse", "davfs2", "9p", "virtiofs"
    };

    ctx.isWindowsFs = windowsFsTypes.contains(ctx.fsType);
    ctx.isLinuxFs   = linuxFsTypes.contains(ctx.fsType);
    ctx.isMacFs     = macFsTypes.contains(ctx.fsType);
    ctx.isNetworkFs = networkFsTypes.contains(ctx.fsType)
                   || ctx.fsType.startsWith("fuse.");

    // FAT variants are almost always removable media (USB sticks, SD cards)
    ctx.isRemovable = (ctx.fsType == "vfat"  ||
                       ctx.fsType == "fat"   ||
                       ctx.fsType == "fat32" ||
                       ctx.fsType == "exfat");

    // If QStorageInfo couldn't identify the type, fall back to the host OS
    if (!ctx.isWindowsFs && !ctx.isLinuxFs && !ctx.isMacFs && !ctx.isNetworkFs) {
        if (ctx.runningOnWindows)     ctx.isWindowsFs = true;
        else if (ctx.runningOnMac)    ctx.isMacFs     = true;
        else                           ctx.isLinuxFs   = true;
    }

    return ctx;
}

// ============================================================================
// buildFilterLists  –  populates all detection lists based on m_ctx
// ============================================================================
void FileScannerWorker::buildFilterLists()
{
    // Convenience flags
    const bool winCtx = m_ctx.isWindowsFs
                     || m_ctx.isRemovable      // removable media can carry Windows payloads
                     || m_ctx.runningOnWindows;
    const bool macCtx = m_ctx.isMacFs
                     || m_ctx.runningOnMac;
    const bool linCtx = m_ctx.isLinuxFs
                     || m_ctx.runningOnLinux;

    // -----------------------------------------------------------------------
    // HIGH-RISK extensions
    //
    // PE launchers (.exe .scr .cpl .pif) are always flagged: even on Linux
    // a stray .exe outside of Wine/Steam paths warrants attention (it shouldn't
    // be there, and trusted paths already whitelist Wine/Steam directories).
    //
    // Windows scripting formats (.bat .cmd .vbs .ps1 …) are only relevant on
    // Windows or Windows-formatted media; on native Linux/macOS ext4/APFS they
    // are inert data and would generate constant noise.
    // -----------------------------------------------------------------------
    m_highRiskExtensions = {
        "exe", "scr", "cpl", "pif"
    };

    if (winCtx) {
        m_highRiskExtensions.append({
            "bat", "cmd",
            "vbs", "vbe", "hta",
            "ps1", "psm1",
            "reg",
            "lnk"
        });
    }

    // -----------------------------------------------------------------------
    // SUSPICIOUS extensions
    //
    // Office macro formats are a cross-platform threat (they can be opened on
    // any OS and phone home or drop payloads via macros).
    //
    // Windows-specific formats (dll, script hosts, installers) only apply in
    // a Windows context.
    //
    // .js / .jse are Windows Script Host formats. On a Linux ext4 workstation
    // JavaScript files are ubiquitous (Node, web dev) and must NOT be flagged.
    //
    // .iso / .img are legitimate on Linux (distro ISOs, disk backups) but
    // suspicious on Windows systems or removable media.
    // -----------------------------------------------------------------------
    m_suspiciousExtensions = {
        // Office macro-enabled formats – flagged everywhere
        "xlsm", "xlsb", "docm", "dotm", "pptm", "ppam"
    };

    if (winCtx) {
        m_suspiciousExtensions.append({
            "dll",
            "js", "jse",        // Windows Script Host JS – NOT web JS
            "wsf", "wsh",
            "msi", "msp", "msc"
        });
    }

    if (winCtx || macCtx || m_ctx.isRemovable) {
        // Disk images: suspicious on Windows/macOS/removable but NOT on a
        // Linux workstation where ISOs are routine downloads.
        m_suspiciousExtensions.append({ "iso", "img" });
    }

    // -----------------------------------------------------------------------
    // NAME FRAGMENTS – highly specific to known malware tooling.
    // Intentionally short list; context-independent.
    // -----------------------------------------------------------------------
    m_suspiciousNameFragments = {
        "keylog",
        "dropper",
        "exploit",
        "rootkit",
        "backdoor",
        "ransomware",
        "coinminer", "xmrig",
        "botnet", "c2agent",
        "stealer",
        "mimikatz",
        "metasploit",
        "shellcode",
        "hvnc"
    };

    // -----------------------------------------------------------------------
    // KNOWN MALWARE / PUA – exact filename (lowercase, with or without ext)
    // Context-independent: these specific names are always suspicious.
    // -----------------------------------------------------------------------
    m_knownMalwareNames = {
        "autorun.inf",
        "svchost32", "svch0st",
        "lsass32",   "csrss32",
        "explorer32", "winlogon32",
        "spoolsv32",  "taskhost32",
        "conhost32",  "wuauclt32",
        "wininit32",  "notpad",
        "regsrv32",   "rundl132",
        "wmiprvs3",   "iexplorer",
        "xmrig", "nanominer", "minerd",
        "psexec", "mimikatz",
        "cobaltstrike", "msfvenom",
        "powersploit", "empire",
        "invoke-mimikatz",
        "bloodhound", "sharphound"
    };

    // -----------------------------------------------------------------------
    // SKIP DIR FRAGMENTS
    // Only load platform-relevant paths to avoid unnecessary string matching.
    // -----------------------------------------------------------------------

    // Universal noise (applies on every platform)
    m_skipDirFragments = {
        "/node_modules/",
        "/.git/",
        "/.local/share/trash",
        "/.trash"
    };

    if (linCtx) {
        m_skipDirFragments.append({
            // Linux virtual filesystems – never real files
            "/proc/", "/sys/", "/dev/", "/run/",
            // Steam / Proton runtimes (thousands of legitimate .so/.sh files)
            "/steamrt", "/steam-runtime",
            "/steamlinuxruntime",
            "/pressure-vessel", "/pv-runtime",
            // Package manager caches
            "/.cache/pip",
            "/.cache/yarn",
            "/.cache/npm",
            "/.cache/cargo",
            "/go/pkg/mod/cache"
        });
    }

    if (macCtx) {
        m_skipDirFragments.append({
            "/system/library/caches",
            "/private/var/vm",
            "/.spotlight-v100",
            "/.fseventsd",
            "/.mobilebackups"
        });
    }

    if (winCtx) {
        m_skipDirFragments.append({
            "\\windows\\winsxs",
            "\\windows\\installer",
            "\\windows\\softwaredistribution",
            "\\$recycle.bin",
            "\\system volume information"
        });
    }

    // -----------------------------------------------------------------------
    // TRUSTED PATH FRAGMENTS
    // Files here skip all extension checks; magic-byte mismatches still fire.
    // -----------------------------------------------------------------------

    // Universal user-managed toolchains and build artefacts
    m_trustedPathFragments = {
        "/.rustup/", "/.cargo/",
        "/.pyenv/", "/.rbenv/",
        "/.nvm/", "/.sdkman/", "/.asdf/",
        "/go/pkg/",
        "/.gradle/", "/.m2/", "/.conan/",
        "/cmake-build", "/build/", "/dist/",
        "/.venv/", "/virtualenv/", "/site-packages/"
    };

    if (linCtx) {
        m_trustedPathFragments.append({
            // Linux system / package manager trees
            "/usr/", "/lib/",
            "/lib32/", "/lib64/", "/libx32/",
            "/bin/", "/sbin/",
            "/etc/", "/var/lib/",
            "/opt/", "/snap/",
            "/var/lib/flatpak",
            "/run/host/",
            "/nix/store/",
            // Flatpak & snap user installs
            "/.local/share/flatpak",
            "/var/lib/snapd",
            // Steam & gaming
            "/.steam/",
            "/.local/share/steam",
            "/steamapps/",
            // Wine prefixes – contain legitimate Windows DLLs / EXEs
            "/.wine/",
            // XDG user data & config dirs (apps legitimately place scripts here)
            "/.local/share/",
            "/.local/bin/",
            "/.config/",
            // Common IDE paths
            "/qt/", "/kde/"
        });
    }

    if (macCtx) {
        m_trustedPathFragments.append({
            "/system/", "/library/",
            "/applications/", "/developer/"
        });
    }

    if (winCtx) {
        m_trustedPathFragments.append({
            "\\windows\\",
            "\\program files\\",
            "\\program files (x86)\\",
            "\\programdata\\",
            "\\windows\\system32",
            "\\windows\\syswow64"
        });
    }

    // -----------------------------------------------------------------------
    // PERSISTENCE DIRS – only load paths relevant to detected platform(s).
    // Moving this out of checkByLocation allows context-aware filtering.
    // -----------------------------------------------------------------------
    m_persistenceDirs.clear();

    if (linCtx) {
        m_persistenceDirs.append({
            "/etc/cron.d/",
            "/etc/cron.daily/",
            "/etc/cron.hourly/",
            "/etc/cron.weekly/",
            "/.config/autostart/"
        });
    }

    if (macCtx) {
        m_persistenceDirs.append({
            "/library/launchagents/",
            "/library/launchd/"
        });
    }

    if (winCtx) {
        m_persistenceDirs.append({
            "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\",
            "\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\"
        });
    }
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
    m_ctx = detectContext(rootPath);
    buildFilterLists();
}

// ============================================================================
// shouldSkipDirectory
// ============================================================================
bool FileScannerWorker::shouldSkipDirectory(const QString& lowerDirPath) const
{
    for (const QString& frag : m_skipDirFragments) {
        if (lowerDirPath.contains(frag))
            return true;
    }
    return false;
}

// ============================================================================
// isTrustedPath
// ============================================================================
bool FileScannerWorker::isTrustedPath(const QString& lowerAbsPath) const
{
    for (const QString& frag : m_trustedPathFragments) {
        if (lowerAbsPath.contains(frag))
            return true;
    }
    return false;
}

// ============================================================================
// isVersionedSharedLib
// ============================================================================
bool FileScannerWorker::isVersionedSharedLib(const QString& lowerFileName, const QString& ext)
{
    // Plain .so or .dylib
    if (ext == "so" || ext == "dylib")
        return true;

    // Anything containing ".so" (covers libfoo.so.1.2.3, libbar.so.0, etc.)
    if (lowerFileName.contains(".so"))
        return true;

    // Versioned number-only suffix after a .so chain (e.g. ".62" in libSDL.so.0.3200.62)
    static const QRegularExpression reDigits(QStringLiteral("^\\d+$"));
    if (reDigits.match(ext).hasMatch() && lowerFileName.contains(".so"))
        return true;

    return false;
}

// ============================================================================
// checkByNameAndExtension
// ============================================================================
bool FileScannerWorker::checkByNameAndExtension(const QString& fileName,
                                                  const QString& lowerName,
                                                  const QString& lowerPath,
                                                  QString& outReason,
                                                  QString& outCategory) const
{
    // 1. Known malware name – always checked
    for (const QString& known : m_knownMalwareNames) {
        if (lowerName == known || lowerName.startsWith(known + ".")) {
            outCategory = "Known Malware / PUA Name";
            outReason   = QString("Filename \"%1\" matches a known malware or PUA name.").arg(fileName);
            return true;
        }
    }

    // 2. Suspicious name fragment – always checked, but not in trusted paths
    if (!isTrustedPath(lowerPath)) {
        for (const QString& frag : m_suspiciousNameFragments) {
            if (lowerName.contains(frag)) {
                outCategory = "Suspicious Name Pattern";
                outReason   = QString("Filename contains malware-associated keyword \"%1\".").arg(frag);
                return true;
            }
        }
    }

    // Shared-lib soname → never flag by extension
    const QString ext = QFileInfo(fileName).suffix().toLower();
    if (isVersionedSharedLib(lowerName, ext))
        return false;

    // In a trusted path → skip all extension checks
    if (isTrustedPath(lowerPath))
        return false;

    // 3. Double-extension trick: something.pdf.exe, invoice.docx.bat, etc.
    if (fileName.count('.') >= 2 && m_highRiskExtensions.contains(ext)) {
        outCategory = "Double-Extension Trick";
        outReason   = QString("File uses multiple extensions ending in \".%1\", "
                              "a social-engineering technique.").arg(ext);
        return true;
    }

    // 4. High-risk extension outside trusted paths
    if (m_highRiskExtensions.contains(ext)) {
        outCategory = "High-Risk Executable Extension";
        outReason   = QString("Extension \".%1\" is an executable/script type "
                              "frequently used to deliver malware.").arg(ext);
        return true;
    }

    // 5. Suspicious (but less critical) extension outside trusted paths
    if (m_suspiciousExtensions.contains(ext)) {
        outCategory = "Suspicious Extension";
        outReason   = QString("Extension \".%1\" is associated with scripts or "
                              "macro-enabled documents outside a system directory.").arg(ext);
        return true;
    }

    return false;
}

// ============================================================================
// checkByLocation
// ============================================================================
bool FileScannerWorker::checkByLocation(const QString& lowerPath,
                                         const QString& ext,
                                         QString& outReason,
                                         QString& outCategory) const
{
    const bool isExecOrScript =
        m_highRiskExtensions.contains(ext) || m_suspiciousExtensions.contains(ext);

    // Temp directories: only flag executables / scripts.
    // These entries are valid across all platforms so no context gate needed.
    static const QVector<QString> tempDirs = {
        "/tmp/", "/var/tmp/", "/dev/shm/",
        "\\temp\\", "\\tmp\\",
        "\\appdata\\local\\temp\\"
    };
    for (const QString& loc : tempDirs) {
        if (lowerPath.contains(loc) && isExecOrScript) {
            outCategory = "Executable in Temp Directory";
            outReason   = QString("Executable/script found in temp directory (%1). "
                                  "Malware frequently stages payloads in temp dirs.").arg(loc.trimmed());
            return true;
        }
    }

    // Persistence locations: populated per-platform in buildFilterLists()
    for (const QString& loc : m_persistenceDirs) {
        if (lowerPath.contains(loc)) {
            outCategory = "File in Persistence Location";
            outReason   = QString("File resides in a system persistence/autostart "
                                  "directory (%1).").arg(loc.trimmed());
            return true;
        }
    }

    return false;
}

// ============================================================================
// checkByMagicBytes  (reads first 32 bytes only)
// ============================================================================
bool FileScannerWorker::checkByMagicBytes(const QString& filePath,
                                           const QString& ext,
                                           QString& outReason,
                                           QString& outCategory) const
{
    // Skip expensive I/O on network filesystems
    if (m_ctx.isNetworkFs)
        return false;

    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly))
        return false;

    const QByteArray header = f.read(32);
    f.close();

    if (header.size() < 4)
        return false;

    const QString lowerName = QFileInfo(filePath).fileName().toLower();

    // -- Windows PE (MZ) --
    if (header[0] == 'M' && header[1] == 'Z') {
        static const QVector<QString> okExts = {
            "exe","dll","scr","cpl","com","pif","sys","drv","ocx","mui","efi","ax"
        };
        if (!okExts.contains(ext)) {
            outCategory = "PE Binary With Misleading Extension";
            outReason   = QString("Windows PE magic (MZ) found in a file with extension \".%1\". "
                                  "Classic disguise for executables.").arg(ext);
            return true;
        }
    }

    // -- ELF --
    if ((unsigned char)header[0] == 0x7f &&
        header[1] == 'E' && header[2] == 'L' && header[3] == 'F')
    {
        static const QVector<QString> okExts = {
            "so","elf","bin","out","run","axf","prx","ko","o","","appimage"
        };
        if (!okExts.contains(ext) && !isVersionedSharedLib(lowerName, ext)) {
            outCategory = "ELF Binary With Misleading Extension";
            outReason   = QString("Linux/macOS ELF header found in a file with extension \".%1\". "
                                  "Hides a native binary inside a non-executable file.").arg(ext);
            return true;
        }
    }

    // -- Mach-O --
    quint32 magic;
    memcpy(&magic, header.constData(), 4);
    if (magic == 0xFEEDFACEu || magic == 0xFEEDFACFu ||
        magic == 0xCEFAEDFEu || magic == 0xCFFAEDFEu)
    {
        static const QVector<QString> okExts = {
            "dylib","o","a","bundle","so","",
            "app","framework","kext","plugin","macho","nib"
        };
        if (!okExts.contains(ext)) {
            outCategory = "Mach-O Binary With Misleading Extension";
            outReason   = QString("macOS Mach-O header found in a file with extension \".%1\".").arg(ext);
            return true;
        }
    }

    // -- PDF magic in an executable container --
    if (header[0] == '%' && header[1] == 'P' && header[2] == 'D' && header[3] == 'F') {
        static const QVector<QString> exeExts = {"exe","scr","com","bat","cmd"};
        if (exeExts.contains(ext)) {
            outCategory = "PDF Magic in Executable File";
            outReason   = "PDF header bytes found inside an executable-extension file. "
                          "Possible polyglot exploit.";
            return true;
        }
    }

    // -- ZIP/JAR/APK disguised as an image --
    if ((unsigned char)header[0] == 0x50 && (unsigned char)header[1] == 0x4B &&
        (unsigned char)header[2] == 0x03 && (unsigned char)header[3] == 0x04)
    {
        static const QVector<QString> imgExts = {"jpg","jpeg","png","gif","bmp","ico","webp"};
        if (imgExts.contains(ext)) {
            outCategory = "Archive Hidden as Image";
            outReason   = "ZIP-based archive disguised as an image. "
                          "Used to bypass email/web content filters.";
            return true;
        }
    }

    return false;
}

// ============================================================================
// doScan
// ============================================================================
void FileScannerWorker::doScan()
{
    QFileInfo rootInfo(m_rootPath);
    if (!rootInfo.exists() || !rootInfo.isDir()) {
        emit scanError(QString("Root path does not exist or is not a directory: %1")
                           .arg(m_rootPath));
        return;
    }

    QElapsedTimer wallTimer;
    wallTimer.start();

    int     totalScanned    = 0;
    int     suspiciousCount = 0;
    int     dirCount        = 0;
    qint64  totalBytes      = 0;

    const int targetDirs     = 500;
    int       lastProgress   = 0;

    QDirIterator it(
        m_rootPath,
        QDir::Files | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot,
        QDirIterator::Subdirectories   // NO FollowSymlinks – avoids loops
    );

    QString lastDir;

    while (it.hasNext()) {
        if (m_cancelFlag->loadRelaxed() != 0)
            break;

        it.next();
        const QFileInfo fi = it.fileInfo();

        const QString absPath   = fi.absoluteFilePath();
        const QString dirPath   = fi.absolutePath();
        const QString lowerDir  = dirPath.toLower();
        const QString lowerPath = absPath.toLower();

        if (shouldSkipDirectory(lowerDir))
            continue;

        // -- Directory change: update progress + path label --
        if (dirPath != lastDir) {
            lastDir = dirPath;
            ++dirCount;
            emit scanningPath(dirPath);

            int newProgress = qMin(95, (dirCount * 95) / targetDirs);
            if (newProgress != lastProgress) {
                lastProgress = newProgress;
                emit progressUpdated(newProgress);
            }

            // Yield every 200 dirs to keep signals flowing
            if (dirCount % 200 == 0)
                QThread::yieldCurrentThread();
        }

        ++totalScanned;
        totalBytes += fi.size();

        const QString fileName  = fi.fileName();
        const QString lowerName = fileName.toLower();
        const QString ext       = fi.suffix().toLower();

        QString reason, category;

        bool flagged = checkByNameAndExtension(fileName, lowerName, lowerPath, reason, category);
        if (!flagged)
            flagged = checkByLocation(lowerPath, ext, reason, category);
        if (!flagged && fi.size() > 0 && fi.size() < 512LL * 1024 * 1024)
            flagged = checkByMagicBytes(absPath, ext, reason, category);

        if (flagged) {
            SuspiciousFile sf;
            sf.filePath     = absPath;
            sf.fileName     = fileName;
            sf.reason       = reason;
            sf.category     = category;
            sf.sizeBytes    = fi.size();
            sf.lastModified = fi.lastModified();
            emit suspiciousFileFound(sf);
            ++suspiciousCount;
        }
    }

    emit progressUpdated(100);
    int elapsed = static_cast<int>(wallTimer.elapsed() / 1000);
    emit scanFinished(totalScanned, suspiciousCount, elapsed, totalBytes);
}

// ============================================================================
// FileScanner  –  controller
// ============================================================================
FileScanner::FileScanner(QObject* parent)
    : QObject(parent)
{}

FileScanner::~FileScanner()
{
    cancelScan();
}

bool FileScanner::isRunning() const
{
    return m_thread && m_thread->isRunning();
}

void FileScanner::startScan(const QString& rootPath)
{
    if (m_thread && m_thread->isRunning()) {
        cancelScan();
    }

    m_cancelFlag.storeRelaxed(0);

    m_thread = new QThread(this);
    m_worker = new FileScannerWorker(rootPath, &m_cancelFlag);
    m_worker->moveToThread(m_thread);

    connect(m_thread, &QThread::finished, m_worker, &QObject::deleteLater);
    connect(m_thread, &QThread::finished, m_thread, &QObject::deleteLater);
    connect(m_thread, &QThread::finished, this, &FileScanner::onThreadFinished);
    connect(m_thread, &QThread::started,  m_worker, &FileScannerWorker::doScan);

    connect(m_worker, &FileScannerWorker::scanFinished, m_thread, &QThread::quit);
    connect(m_worker, &FileScannerWorker::scanError,    m_thread, &QThread::quit);

    connect(m_worker, &FileScannerWorker::scanningPath,
            this,     &FileScanner::scanningPath,
            Qt::QueuedConnection);
    connect(m_worker, &FileScannerWorker::progressUpdated,
            this,     &FileScanner::progressUpdated,
            Qt::QueuedConnection);
    connect(m_worker, &FileScannerWorker::suspiciousFileFound,
            this,     &FileScanner::suspiciousFileFound,
            Qt::QueuedConnection);
    connect(m_worker, &FileScannerWorker::scanFinished,
            this,     &FileScanner::scanFinished,
            Qt::QueuedConnection);
    connect(m_worker, &FileScannerWorker::scanError,
            this,     &FileScanner::scanError,
            Qt::QueuedConnection);

    m_thread->start();
}

void FileScanner::cancelScan()
{
    if (!m_thread)
        return;

    m_cancelFlag.storeRelaxed(1);

    if (m_thread->isRunning()) {
        m_thread->quit();
        if (!m_thread->wait(4000)) {
            m_thread->terminate();
            m_thread->wait(1000);
        }
    }

    m_thread = nullptr;
    m_worker = nullptr;
}

void FileScanner::onThreadFinished()
{
    m_thread = nullptr;
    m_worker = nullptr;
}
