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

    // ---- Directories to skip entirely ----
    // System virtual dirs, package caches, version control, and build artifacts.
    // Build directories contain compiled objects and generated files that
    // trigger false positives and have no security value to scan.
    m_skipDirFragments = {
        "/node_modules/",
        "/.git/",
        "/.local/share/trash",
        "/.trash",

        // Build artifacts and generated files
        "/build/",
        "/cmake-build-",            // CLion build dirs (cmake-build-debug, etc.)
        "/CMakeFiles/",
        "/__pycache__/",
        "/.pytest_cache/",
        "/.mypy_cache/",
        "/.tox/",
        "/.venv/",
        "/venv/",
        "/env/",
        "/.eggs/",
        "/.build/",                 // Swift build dir
        "/target/",                 // Rust/Maven build dir
        "/out/",                    // Gradle/Android build dir
        "/dist/",                   // JS/Python dist
        "/.next/",                  // Next.js build
        "/.nuxt/",                  // Nuxt.js build

        // IDE metadata
        "/.idea/",
        "/.vscode/",
        "/.vs/",
        "/xcuserdata/",
        "/.gradle/",

        // ── Package manager / vendor directories (high false-positive noise) ──
        "/site-packages/",          // Python pip-installed packages
        "/vendor/",                 // Go, Ruby, PHP vendor deps
        "/Pods/",                   // CocoaPods (macOS/iOS)
        "/Carthage/",              // Carthage (macOS/iOS)
        "/.pub-cache/",            // Dart/Flutter
        "/.npm/",                  // npm cache
        "/.yarn/",                 // Yarn cache

        // ── Packaged application resources (low scan value) ──
        "/.app/Contents/Resources/",  // macOS .app bundle resources
        "/.app/Contents/Frameworks/", // macOS .app embedded frameworks
        "/Resources/",                // General app resources
        "/.chrome/",                  // Chrome profile data
        "/.mozilla/",                 // Firefox profile data
        "/Extensions/",              // Browser/app extensions

        // ── Chromium / Electron internals (high entropy by design) ──
        "/Chromium Embedded Framework/",  // CEF in Spotify, Slack, etc.
        "/Code Cache/",                   // Chrome/Chromium compiled JS cache
        "/Electron/",                     // Electron framework dir
        "/nwjs/",                         // NW.js (Node-Webkit) framework
        "/CefSharp/",                     // CefSharp .NET browser control
        "/Service Worker/",              // Chrome service worker cache

        // ── Runtime / managed code artifacts ──
        "/.cargo/registry",         // Rust crate cache
        "/gems/",                   // Ruby gems
        "/.m2/repository",          // Maven local cache
        "/.nuget/",                 // .NET NuGet cache
        "/.cache/go-build",         // Go build cache
    };

    if (linCtx) {
        m_skipDirFragments.append({
            "/proc/", "/sys/", "/dev/", "/run/",
            // Steam runtime containers (already skipped)
            "/steamrt", "/steam-runtime",
            "/steamlinuxruntime",
            "/pressure-vessel", "/pv-runtime",
            // Steam game library — game assets, Proton DLLs, shader caches.
            // These generate massive FP noise (high-entropy packed game data,
            // Proton/Wine PE DLLs that look suspicious to the PE model).
            // The Steam client itself verifies file integrity via depot hashes.
            "/steamapps/common/",
            "/steamapps/shadercache/",
            "/steamapps/downloading/",
            "/steamapps/temp/",
            "/.steam/steam/steamapps/",
            "/.local/share/Steam/steamapps/",
            "/.cache/pip", "/.cache/yarn",
            "/.cache/npm", "/.cache/cargo",
            "/go/pkg/mod/cache",
            // System managed libraries (dpkg / rpm territory)
            "/usr/lib/python",             // system Python packages
            "/usr/share/",                 // man pages, icons, docs
            "/usr/lib/x86_64-linux-gnu/",  // system shared libs
            "/usr/lib/aarch64-linux-gnu/",
            "/snap/",                      // snap-packaged apps
        });
    }
    if (macCtx) {
        m_skipDirFragments.append({
            "/system/library/caches", "/private/var/vm",
            "/.spotlight-v100", "/.fseventsd", "/.mobilebackups",
            // macOS packaged app internals (massive false-positive source)
            "/Library/Application Support/",
            "/Contents/MacOS/",         // app binary dir (managed by Gatekeeper)
            "/Contents/_CodeSignature/",
            "/Contents/Frameworks/",
            "/Contents/PlugIns/",
            // Homebrew (installed & managed packages)
            "/usr/local/Cellar/",
            "/opt/homebrew/Cellar/",
            "/usr/local/lib/",
            "/opt/homebrew/lib/",
            // Xcode
            "/Xcode.app/",
            "/DerivedData/",
            "/Developer/Platforms/",
            // Steam game library (macOS)
            "/steamapps/common/",
            "/steamapps/shadercache/",
            "/Library/Application Support/Steam/steamapps/",
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
        // Compiled objects and libraries
        "so", "ko", "o", "a", "pyc", "pyo", "pyd",
        "class", "obj", "lib", "lo", "la",
        // Fonts
        "ttf", "otf", "woff", "woff2",
        // Images
        "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp", "tiff",
        // Audio
        "mp3", "wav", "flac", "ogg", "aac", "m4a",
        // Video
        "mp4", "avi", "mkv", "mov", "webm",
        // Databases
        "db", "sqlite", "sqlite3",
        // Logs & data
        "log", "csv", "tsv",
        // macOS-specific assets
        "nib", "storyboardc", "car",  // Interface Builder + asset catalogs
        "strings", "plist",            // property lists
        "tbd",                         // text-based stub libraries
        "modulemap",                   // Clang module maps
        // Chromium/Electron resources
        "pak",                         // Chromium resource pack
        "asar",                        // Electron archive
        // Game engine and asset formats
        // These are binary data files — they will never appear in a malware
        // hash database and generate severe false positives, especially for
        // packed/encrypted game assets (high entropy by design).
        "tga",                         // Targa image (Valve, Quake engines)
        "spr",                         // Valve sprite
        "vtf",                         // Valve Texture Format
        "vmt",                         // Valve Material Type
        "bsp",                         // BSP map (Quake/Source engine)
        "mdl",                         // 3D model (Source, Quake)
        "vpk",                         // Valve Pak archive
        "nav",                         // Navigation mesh
        "vvd",                         // Vertex animation data
        "dx80", "dx90",                // DirectX mesh data
        "gcf",                         // Game Cache File (legacy Steam)
        "acf",                         // Steam app config / manifest
        "ncf",                         // Node Content File (Steam)
        "pcf",                         // Particle effect file
        "vtx",                         // Vertex strip file
        "phy",                         // Physics collision data
        "ani",                         // Animation file
        "ain",                         // AI node file
        "lmp",                         // Quake lump / Doom lump
        "wad",                         // Quake/Doom texture archive
        "pk3", "pk4",                  // Quake III / Quake 4 pak
        "pak",                         // Quake I/II pak (also Chromium above)
        "res",                         // Half-Life resource file
        "xtx", "dds",                  // DirectDraw Surface / Nintendo textures
        "pvr",                         // PowerVR texture
        "ktx",                         // Khronos texture
        "hdr",                         // HDR image (game skyboxes)
        "exr",                         // OpenEXR (VFX / game rendering)
    };
}

// ============================================================================
// FileScannerWorker – constructor
// ============================================================================
FileScannerWorker::FileScannerWorker(const QString&           rootPath,
                                     QAtomicInt*              cancelFlag,
                                     QHash<QString, CacheEntry> scanCache,
                                     const QString&           resumeFromDir,
                                     QObject*                 parent)
    : QObject(parent)
    , m_rootPath(rootPath)
    , m_cancelFlag(cancelFlag)
    , m_resumeFromDir(resumeFromDir)
    , m_scanCache(std::move(scanCache))
{
    m_ctx    = detectContext(rootPath);
    buildFilterLists();
    m_hashDb = loadHashDatabase();
}