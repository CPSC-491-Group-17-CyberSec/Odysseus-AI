#include "FileScanner.h"

#include <QDirIterator>
#include <QFileInfo>
#include <QFile>
#include <QDir>
#include <QElapsedTimer>
#include <QThread>
#include <QRegularExpression>

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
    // -----------------------------------------------------------------------
    // HIGH-RISK extensions – flagged regardless of path unless whitelisted.
    // Shell scripts (.sh) are intentionally omitted: they are ubiquitous in
    // package installs, build systems, and dotfile managers.
    // -----------------------------------------------------------------------
    m_highRiskExtensions = {
        // Windows executables & loaders
        "exe", "scr", "cpl", "pif",
        // Windows scripting / automation
        "bat", "cmd", "vbs", "vbe", "hta",
        "ps1", "psm1",
        // Windows registry & installer formats that can auto-run
        "reg",
        // Shortcut files – widely abused as LNK exploits
        "lnk"
    };

    // -----------------------------------------------------------------------
    // SUSPICIOUS extensions – flagged only OUTSIDE trusted paths.
    // .dll is here (not high-risk) because virtually every app ships DLLs.
    // -----------------------------------------------------------------------
    m_suspiciousExtensions = {
        "dll",        // flagged only outside trusted dirs
        "js", "jse",  // Windows JS scripts
        "wsf", "wsh",
        "msi", "msp", "msc",
        // Office macro-enabled formats
        "xlsm", "xlsb", "docm", "dotm", "pptm", "ppam",
        // Disk images used to deliver malware
        "iso", "img"
    };

    // -----------------------------------------------------------------------
    // NAME FRAGMENTS – these are highly specific to known malware tooling.
    // Intentionally short list to avoid matching legitimate software.
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
    // KNOWN MALWARE / PUA – exact filename (with or without extension, lowercase)
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
    // SKIP DIR FRAGMENTS – never descend into these subtrees.
    // Matched case-insensitively against the lowercase absolute dir path.
    // -----------------------------------------------------------------------
    m_skipDirFragments = {
        // Linux virtual filesystems
        "/proc/", "/sys/", "/dev/", "/run/",
        // macOS virtual / spotlight / TM
        "/system/library/caches",
        "/private/var/vm",
        "/.spotlight-v100",
        "/.fseventsd",
        "/.mobilebackups",
        // Windows heavyweight caches
        "\\windows\\winsxs",
        "\\windows\\installer",
        "\\windows\\softwaredistribution",
        "\\$recycle.bin",
        "\\system volume information",
        // Universal noise
        "/node_modules/",
        "/.git/",
        // Steam / Proton / Pressure-vessel runtimes
        // (thousands of legitimate .so/.sh files)
        "/steamrt",
        "/steam-runtime",
        "/steamlinuxruntime",
        "/pressure-vessel",
        "/pv-runtime",
        // Package manager caches
        "/.cache/pip",
        "/.cache/yarn",
        "/.cache/npm",
        "/.cache/cargo",
        "/go/pkg/mod/cache",
        // Trash
        "/.local/share/trash",
        "/.trash"
    };

    // -----------------------------------------------------------------------
    // TRUSTED PATH FRAGMENTS
    // Files here skip all extension-based checks.
    // Magic-byte mismatches (e.g. PE inside a .jpg) still fire everywhere.
    // Matched case-insensitively against lowercase absolute path.
    // -----------------------------------------------------------------------
    m_trustedPathFragments = {
        // Linux system / package manager directories
        "/usr/",
        "/lib/",
        "/lib32/",
        "/lib64/",
        "/libx32/",
        "/bin/",
        "/sbin/",
        "/etc/",
        "/var/lib/",
        "/opt/",
        "/snap/",
        "/var/lib/flatpak",
        "/run/host/",

        // macOS system
        "/system/",
        "/library/",
        "/applications/",
        "/developer/",

        // Windows system
        "\\windows\\",
        "\\program files\\",
        "\\program files (x86)\\",
        "\\programdata\\",
        "\\windows\\system32",
        "\\windows\\syswow64",

        // User-managed toolchains (language version managers, etc.)
        "/.rustup/",
        "/.cargo/",
        "/.pyenv/",
        "/.rbenv/",
        "/.nvm/",
        "/.sdkman/",
        "/.asdf/",
        "/go/pkg/",
        "/nix/store/",

        // Flatpak & snap user installs
        "/.local/share/flatpak",
        "/var/lib/snapd",

        // Steam & gaming – kept broad since the dir-skip covers runtimes
        "/.steam/",
        "/.local/share/steam",
        "/steamapps/",

        // Common IDE / build artefacts
        "/.local/share/",     // XDG user data – apps legitimately put scripts here
        "/.config/",          // XDG config – dotfile scripts are expected here
        "/qt/",
        "/kde/",
        "/.gradle/",
        "/.m2/",
        "/.conan/",
        "/cmake-build",
        "/build/",
        "/dist/",
        "/.venv/",
        "/virtualenv/",
        "/site-packages/"
    };
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

    // 2. Suspicious name fragment – always checked, but only if NOT a trusted path
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

    // Temp directories: only flag executables / scripts
    static const QStringList tempDirs = {
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

    // Persistence locations: flag any file (not just executables)
    static const QStringList persistenceDirs = {
        "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\",
        "\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\",
        "/library/launchagents/",
        "/library/launchd/",
        "/etc/cron.d/", "/etc/cron.daily/",
        "/etc/cron.hourly/", "/etc/cron.weekly/",
        "/.config/autostart/"
    };
    for (const QString& loc : persistenceDirs) {
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
            "so","elf","bin","out","run","axf","prx","ko","o",""
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

    int totalScanned    = 0;
    int suspiciousCount = 0;
    int dirCount        = 0;   // for progress estimation

    // We don't know total file count upfront, so use a time-based sigmoid:
    // progress = 1 - e^(-k*t) mapped to 0..95 while running.
    // Simpler alternative used here: increment per-directory, cap at 95.
    // The exact per-dir increment uses a target of ~500 dirs = 95%.
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

            // Linear progress 0→95 over first `targetDirs` directories
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
    emit scanFinished(totalScanned, suspiciousCount, elapsed);
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

// Key fix for SIGSEGV:
// Previous code set m_thread/m_worker to nullptr THEN let deleteLater fire –
// causing a double-free or use-after-free.  The correct pattern is:
//   • Use QPointer<QThread> so we can safely check after wait().
//   • Never touch m_worker after moveToThread() – it lives on the worker thread.
//   • The deleteLater() chain (thread::finished → worker::deleteLater,
//     thread::finished → thread::deleteLater) handles cleanup automatically.
//   • startScan() creates fresh objects each time; it does NOT reuse old ones.
void FileScanner::startScan(const QString& rootPath)
{
    // If somehow called while still running, cancel first
    if (m_thread && m_thread->isRunning()) {
        cancelScan();
    }

    // Reset cancel flag BEFORE creating new thread/worker
    m_cancelFlag.storeRelaxed(0);

    // Create fresh objects – previous ones were cleaned up via deleteLater
    m_thread = new QThread(this);    // parent = this so Qt tracks it
    m_worker = new FileScannerWorker(rootPath, &m_cancelFlag);
    // Worker has NO parent so it can be safely moved to another thread
    m_worker->moveToThread(m_thread);

    // Worker cleanup: when thread finishes, delete worker (on worker thread),
    // then delete thread (on this thread).
    connect(m_thread, &QThread::finished, m_worker, &QObject::deleteLater);
    connect(m_thread, &QThread::finished, m_thread, &QObject::deleteLater);

    // Null our pointers when the thread object is about to be destroyed,
    // so isRunning() returns false and we don't double-delete.
    connect(m_thread, &QThread::finished, this, &FileScanner::onThreadFinished);

    // Start worker slot when thread starts
    connect(m_thread, &QThread::started, m_worker, &FileScannerWorker::doScan);

    // Quit thread event-loop when worker signals done/error
    connect(m_worker, &FileScannerWorker::scanFinished, m_thread, &QThread::quit);
    connect(m_worker, &FileScannerWorker::scanError,    m_thread, &QThread::quit);

    // Re-emit worker signals to our own listeners (QueuedConnection = cross-thread safe)
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

    // Signal worker to stop iterating
    m_cancelFlag.storeRelaxed(1);

    if (m_thread->isRunning()) {
        m_thread->quit();
        // Wait up to 4 seconds for clean shutdown
        if (!m_thread->wait(4000)) {
            // Force-terminate only as last resort
            m_thread->terminate();
            m_thread->wait(1000);
        }
    }
    // Do NOT call deleteLater here – the finished() signal already does it.
    // Just null our pointers; the objects will self-destruct via the
    // deleteLater chain that was set up in startScan().
    m_thread = nullptr;
    m_worker = nullptr;
}

void FileScanner::onThreadFinished()
{
    // Called on the UI thread when the worker thread's event loop exits.
    // Safe to null these now – deleteLater is already queued.
    m_thread = nullptr;
    m_worker = nullptr;
}