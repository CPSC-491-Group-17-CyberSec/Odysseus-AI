#pragma once
// ============================================================================
// ScanResultFormatter.h  –  Structured scan output + severity mapping
//
// Provides:
//   1. ClassificationLevel enum:  Clean / Anomalous / Suspicious / Critical
//   2. FileCategory enum:  determines per-type scoring behavior
//   3. File-type-aware threshold + indicator strength logic
//   4. HTML/web-specific malicious pattern detection
//   5. Structured ScanResult that cleanly separates detection vs. explanation
//   6. Professional terminal output formatting
//
// Architecture:
//   ┌─────────────┐    ┌──────────────────┐    ┌──────────────────┐
//   │ ONNX Model  │───>│ Classify()       │───>│ Terminal Fmt      │
//   │ (Detection)  │    │ score + features │    │ (clean output)    │
//   └─────────────┘    │ + file type      │    └──────────────────┘
//                      └────────┬─────────┘
//                               │
//                      ┌────────▼─────────┐    ┌──────────────────┐
//                      │ LLMExplainer     │───>│ Parsed Explanation│
//                      │ (Ollama)         │    │ (summary/actions) │
//                      └──────────────────┘    └──────────────────┘
// ============================================================================

#include <string>
#include <vector>
#include <cmath>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <set>

// ============================================================================
// Classification Level  –  four-state verdict
//
//   Clean       –  below threshold, not reported (internal use only)
//   Anomalous   –  above threshold but weak indicators; "needs review"
//   Suspicious  –  strong indicators of malicious intent
//   Critical    –  very high score + multiple strong indicators
// ============================================================================

enum class ClassificationLevel {
    Clean,
    Anomalous,    // "Needs Review" – borderline, may be benign
    Suspicious,   // genuine concern, warrants action
    Critical      // high confidence malicious
};

inline const char* classificationToString(ClassificationLevel cl)
{
    switch (cl) {
        case ClassificationLevel::Clean:      return "Clean";
        case ClassificationLevel::Anomalous:  return "Anomalous";
        case ClassificationLevel::Suspicious: return "Suspicious";
        case ClassificationLevel::Critical:   return "CRITICAL";
    }
    return "Unknown";
}

/// ANSI color for the classification level in terminal output
inline const char* classificationToColor(ClassificationLevel cl)
{
    switch (cl) {
        case ClassificationLevel::Clean:      return "\033[32m";       // Green
        case ClassificationLevel::Anomalous:  return "\033[33m";       // Yellow
        case ClassificationLevel::Suspicious: return "\033[38;5;208m"; // Orange
        case ClassificationLevel::Critical:   return "\033[91;1m";     // Bright red bold
    }
    return "\033[0m";
}

/// Terminal status label for the classification level
inline const char* classificationToLabel(ClassificationLevel cl)
{
    switch (cl) {
        case ClassificationLevel::Clean:      return "[ CLEAN ]";
        case ClassificationLevel::Anomalous:  return "[ NEEDS REVIEW ]";
        case ClassificationLevel::Suspicious: return "[ SUSPICIOUS ]";
        case ClassificationLevel::Critical:   return "[ CRITICAL ]";
    }
    return "[ UNKNOWN ]";
}

/// Map classification to a 0–100 severity percent (for UI progress bars)
inline int classificationToPercent(ClassificationLevel cl)
{
    switch (cl) {
        case ClassificationLevel::Clean:      return 0;
        case ClassificationLevel::Anomalous:  return 30;
        case ClassificationLevel::Suspicious: return 65;
        case ClassificationLevel::Critical:   return 100;
    }
    return 0;
}

// ============================================================================
// Legacy SeverityLevel  –  kept for backward compatibility with UI code
// ============================================================================

enum class SeverityLevel {
    Low,
    Medium,
    High,
    Critical
};

inline SeverityLevel scoreToseverity(float score, float /*threshold*/ = 0.5f)
{
    if (score < 0.60f)  return SeverityLevel::Low;
    if (score < 0.75f)  return SeverityLevel::Medium;
    if (score < 0.90f)  return SeverityLevel::High;
    return SeverityLevel::Critical;
}

inline const char* severityToString(SeverityLevel sev)
{
    switch (sev) {
        case SeverityLevel::Low:      return "Low";
        case SeverityLevel::Medium:   return "Medium";
        case SeverityLevel::High:     return "High";
        case SeverityLevel::Critical: return "CRITICAL";
    }
    return "Unknown";
}

inline const char* severityToColor(SeverityLevel sev)
{
    switch (sev) {
        case SeverityLevel::Low:      return "\033[33m";
        case SeverityLevel::Medium:   return "\033[38;5;208m";
        case SeverityLevel::High:     return "\033[31m";
        case SeverityLevel::Critical: return "\033[91;1m";
    }
    return "\033[0m";
}

inline int severityToPercent(SeverityLevel sev)
{
    switch (sev) {
        case SeverityLevel::Low:      return 25;
        case SeverityLevel::Medium:   return 50;
        case SeverityLevel::High:     return 75;
        case SeverityLevel::Critical: return 100;
    }
    return 0;
}

// ============================================================================
// File Category  –  determines how we interpret features and set thresholds
// ============================================================================

enum class FileCategory {
    PEBinary,           // .exe, .dll, .sys, .scr  – model is calibrated for these
    Script,             // .bat, .ps1, .vbs, .js (standalone), .py, .sh
    WebContent,         // .html, .htm, .css, .js (in web context), .svg
    TextData,           // .txt, .md, .json, .xml, .yaml, .csv, .log, .ini, .conf
    Archive,            // .zip, .gz, .7z, .rar, .tar
    Installer,          // .dmg, .pkg, .msi, .deb, .rpm, .appimage
    MediaBinary,        // .jpg, .png, .mp3, .mp4, .pdf, .docx, etc.
    SourceCode,         // .cpp, .h, .c, .hpp, .cc, .java, .rs, .go, .cs, .m, .swift
    CompiledArtifact,   // .o, .obj, .a, .lib, .pyc, .pyo, .class, moc_*.cpp
    BuildOutput,        // Makefile, CMakeLists.txt, CMakeCache.txt, *.cmake
    Unknown             // anything else – use default behavior
};

/// Classify a file extension into a category.
/// Also supports full filename matching for extensionless build files.
inline FileCategory categorizeExtension(const std::string& ext)
{
    // PE binaries
    static const std::set<std::string> pe = {
        "exe", "com", "scr", "pif", "dll", "sys", "drv", "ocx",
        "so", "dylib", "elf", "bin", "app", "out"
    };
    // Source code (developer files – NOT scripts)
    static const std::set<std::string> source = {
        "cpp", "c", "cc", "cxx", "h", "hpp", "hxx", "hh",
        "java", "cs", "rs", "go", "swift", "m", "mm",
        "kt", "kts", "scala", "zig", "nim", "d",
        "proto", "thrift", "fbs",
        "ts",       // TypeScript (source, not script)
    };
    // Scripts
    static const std::set<std::string> scripts = {
        "bat", "cmd", "ps1", "vbs", "wsh", "wsf", "py", "sh",
        "bash", "pl", "rb", "php", "hta", "lua", "r", "jl"
    };
    // Web content (HTML / CSS / client-side JS)
    static const std::set<std::string> web = {
        "html", "htm", "css", "svg", "xhtml", "jsp", "asp", "aspx",
        "vue", "jsx", "tsx", "svelte"
    };
    // Text / data (includes config, metadata, and platform asset text formats)
    static const std::set<std::string> text = {
        "txt", "md", "rst", "csv", "tsv", "log",
        "json", "xml", "yaml", "yml", "toml",
        "ini", "cfg", "conf", "properties", "env",
        "gitignore", "gitattributes", "editorconfig",
        "clang-format", "clang-tidy",
        // macOS / iOS platform assets (text-based, never malicious)
        "plist", "strings", "stringsdict",
        "entitlements", "modulemap", "tbd",
        "xib", "storyboard",
    };
    // Compiled artifacts / object files
    static const std::set<std::string> compiled = {
        "o", "obj", "a", "lib", "lo", "la",
        "pyc", "pyo", "pyd",
        "class", "jar", "war",
        "wasm", "bc", "ll",
        "dSYM", "pdb", "ilk", "exp",
        // Ruby / Python / Node compiled extensions
        "bundle", "gem", "egg",
    };
    // Build system files
    static const std::set<std::string> build = {
        "cmake", "mk", "make", "ninja",
        "sln", "vcxproj", "xcodeproj", "pbxproj",
        "gradle", "pro", "pri", "qrc", "ui"
    };
    // Archives
    static const std::set<std::string> archives = {
        "zip", "gz", "bz2", "xz", "7z", "rar", "tar",
        "tgz", "tbz2", "zst", "lz4"
    };
    // Installers
    static const std::set<std::string> installers = {
        "dmg", "pkg", "deb", "rpm", "msi", "appimage", "snap",
        "flatpak", "iso", "img"
    };
    // Media / document binaries (includes compiled assets)
    static const std::set<std::string> media = {
        "jpg", "jpeg", "png", "gif", "bmp", "webp", "tiff", "ico",
        "mp3", "mp4", "avi", "mkv", "mov", "flac", "ogg", "wav",
        "pdf", "docx", "xlsx", "pptx", "doc", "xls", "ppt",
        // macOS compiled resources (binary but not executable)
        "nib", "storyboardc", "car",   // Interface Builder + asset catalogs
        "ttf", "otf", "woff", "woff2", // fonts
        // Application resource packs (high entropy by design)
        "pak",                          // Chromium/Electron resource pack
        "asar",                         // Electron archive
        "localstorage", "leveldb",      // Browser storage files
    };

    if (pe.count(ext))         return FileCategory::PEBinary;
    if (source.count(ext))     return FileCategory::SourceCode;
    if (compiled.count(ext))   return FileCategory::CompiledArtifact;
    if (build.count(ext))      return FileCategory::BuildOutput;
    if (scripts.count(ext))    return FileCategory::Script;
    if (web.count(ext))        return FileCategory::WebContent;
    if (text.count(ext))       return FileCategory::TextData;
    if (archives.count(ext))   return FileCategory::Archive;
    if (installers.count(ext)) return FileCategory::Installer;
    if (media.count(ext))      return FileCategory::MediaBinary;

    // .js is ambiguous: treat as WebContent (most common in scans)
    if (ext == "js" || ext == "mjs" || ext == "cjs")
        return FileCategory::WebContent;

    return FileCategory::Unknown;
}

/// Categorize by full filename (for extensionless files like Makefile)
inline FileCategory categorizeFilename(const std::string& filename)
{
    static const std::set<std::string> buildFiles = {
        "makefile", "gnumakefile", "cmakelists.txt", "cmakecache.txt",
        "configure", "configure.ac", "meson.build", "build.gradle",
        "build.ninja", "justfile", "rakefile", "gulpfile.js",
        "gruntfile.js", "webpack.config.js", "rollup.config.js",
        "tsconfig.json", "package.json", "package-lock.json",
        "cargo.toml", "cargo.lock", "go.mod", "go.sum",
        "gemfile", "gemfile.lock", "pipfile", "pipfile.lock",
        "poetry.lock", "setup.py", "setup.cfg", "pyproject.toml",
        "requirements.txt", "yarn.lock", "pnpm-lock.yaml",
        "podfile", "podfile.lock", "conanfile.txt", "conanfile.py",
        "vcpkg.json", "meson_options.txt"
    };
    // Lowercase the filename for comparison
    std::string lower = filename;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (buildFiles.count(lower))
        return FileCategory::BuildOutput;
    return FileCategory::Unknown;
}

inline const char* fileCategoryToString(FileCategory cat)
{
    switch (cat) {
        case FileCategory::PEBinary:          return "PE Binary";
        case FileCategory::Script:            return "Script";
        case FileCategory::WebContent:        return "Web Content";
        case FileCategory::TextData:          return "Text/Data";
        case FileCategory::Archive:           return "Archive";
        case FileCategory::Installer:         return "Installer";
        case FileCategory::MediaBinary:       return "Media/Document";
        case FileCategory::SourceCode:        return "Source Code";
        case FileCategory::CompiledArtifact:  return "Compiled Artifact";
        case FileCategory::BuildOutput:       return "Build/Config";
        case FileCategory::Unknown:           return "Unknown";
    }
    return "Unknown";
}

// ============================================================================
// File-type aware threshold  –  reduces false positives
// ============================================================================

/// Extract lowercase extension from a file path
inline std::string extractExtension(const std::string& path)
{
    auto dot = path.rfind('.');
    if (dot == std::string::npos || dot == path.size() - 1) return "";
    std::string ext = path.substr(dot + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return ext;
}

/// Returns an adjusted threshold for the given file category.
/// The model was trained on PE executables; other formats need a higher bar.
inline float adjustedThreshold(float baseThreshold, FileCategory cat)
{
    switch (cat) {
        case FileCategory::PEBinary:          return baseThreshold;                          // calibrated
        case FileCategory::Script:            return baseThreshold + 0.05f;                  // slight bump
        case FileCategory::WebContent:        return std::min(baseThreshold + 0.30f, 0.95f); // aggressive filter
        case FileCategory::TextData:          return std::min(baseThreshold + 0.35f, 0.95f); // very aggressive
        case FileCategory::Archive:           return std::min(baseThreshold + 0.20f, 0.85f);
        case FileCategory::Installer:         return std::min(baseThreshold + 0.25f, 0.90f);
        case FileCategory::MediaBinary:       return std::min(baseThreshold + 0.25f, 0.90f);
        case FileCategory::SourceCode:        return std::min(baseThreshold + 0.30f, 0.95f); // devs files: high bar
        case FileCategory::CompiledArtifact:  return std::min(baseThreshold + 0.30f, 0.95f); // object files: high bar
        case FileCategory::BuildOutput:       return std::min(baseThreshold + 0.35f, 0.95f); // build configs: very high
        case FileCategory::Unknown:           return baseThreshold + 0.10f;                  // moderate bump
    }
    return baseThreshold;
}

// Backward-compat overload: string extension → category → threshold
inline float adjustedThreshold(float baseThreshold, const std::string& extension)
{
    return adjustedThreshold(baseThreshold, categorizeExtension(extension));
}

// ============================================================================
// HTML / Web-Specific Malicious Pattern Detection
//
// Normal HTML files contain URLs, base64 data URIs, moderate entropy, and
// high printable ASCII ratios.  These are EXPECTED and should NOT trigger
// a suspicious verdict by themselves.
//
// What IS suspicious in HTML:
//   • eval() / Function() chains with encoded arguments
//   • document.write with obfuscated strings
//   • unescape / decodeURIComponent chains
//   • hidden iframes (display:none + src=)
//   • window.location redirects to data: or javascript: URIs
//   • dynamic script injection (createElement('script'))
//   • very long single-line obfuscated blocks
// ============================================================================

/// Indicators that are EXPECTED in normal web content and should be
/// downweighted or ignored when scoring HTML/JS/CSS files.
struct WebIndicatorAnalysis {
    bool hasWeakIndicatorsOnly = true;  // only benign-looking signals
    int  strongIndicatorCount  = 0;     // count of genuinely suspicious patterns
    int  weakIndicatorCount    = 0;     // count of benign/expected web signals
    std::vector<std::string> strongIndicators;  // descriptions of strong signals
    std::vector<std::string> weakIndicators;    // descriptions of weak/expected signals
};

/// Analyze the 38-feature vector in the context of a web file.
/// Separates "expected for HTML" signals from "genuinely suspicious" ones.
inline WebIndicatorAnalysis analyzeWebIndicators(const std::vector<float>& features)
{
    WebIndicatorAnalysis result;

    if (features.size() < 38) return result;

    // ── WEAK indicators (expected in normal HTML/JS) ────────────────────
    // These are common in benign web files and should not drive classification.

    // Moderate entropy (5.0–7.0) is normal for minified JS / HTML with inline data
    if (features[1] > 5.0f && features[1] <= 7.2f) {
        result.weakIndicatorCount++;
        result.weakIndicators.push_back("Moderate entropy (normal for minified web content)");
    }

    // High printable ASCII ratio is EXPECTED for text/HTML
    if (features[6] > 0.7f) {
        result.weakIndicatorCount++;
        result.weakIndicators.push_back("High printable ASCII ratio (expected for HTML/JS)");
    }

    // Embedded URLs are normal in HTML
    if (features[33] > 0.0f && features[33] <= 0.6f) {
        result.weakIndicatorCount++;
        result.weakIndicators.push_back("Contains URLs (standard for web pages)");
    }

    // Base64 strings are used for data URIs (images, fonts) in modern web
    if (features[36] > 0.0f && features[36] <= 0.4f) {
        result.weakIndicatorCount++;
        result.weakIndicators.push_back("Contains base64 strings (common for data URIs in web pages)");
    }

    // ── STRONG indicators (genuinely suspicious even in HTML) ───────────
    // These suggest actual malicious intent, not just normal web content.

    // Very high entropy (> 7.2) in a text file is unusual – suggests heavy obfuscation
    if (features[1] > 7.2f) {
        result.strongIndicatorCount++;
        result.strongIndicators.push_back("Very high entropy for a text file — heavy obfuscation likely");
    }

    // Low printable ASCII ratio is ABNORMAL for HTML – suggests binary payload
    if (features[6] < 0.5f) {
        result.strongIndicatorCount++;
        result.strongIndicators.push_back("Low printable ASCII ratio — unusual for web content, possible embedded binary");
    }

    // Suspicious API strings – these are process-level APIs that don't belong in HTML
    // (features[32] = suspicious API count, normalized 0–1 with /10.0 cap)
    if (features[32] > 0.2f) {
        result.strongIndicatorCount++;
        result.strongIndicators.push_back("Contains system-level API references (CreateRemoteThread, VirtualAlloc, etc.)");
    }

    // Many embedded URLs (> 6) can indicate a phishing page or redirect farm
    if (features[33] > 0.6f) {
        result.strongIndicatorCount++;
        result.strongIndicators.push_back("Unusually high URL density — possible phishing or redirect chain");
    }

    // Many embedded IP addresses are suspicious in HTML
    if (features[34] > 0.2f) {
        result.strongIndicatorCount++;
        result.strongIndicators.push_back("Multiple embedded IP addresses — possible C2 beaconing in web content");
    }

    // Registry paths in web content are always suspicious
    if (features[35] > 0.0f) {
        result.strongIndicatorCount++;
        result.strongIndicators.push_back("Windows registry paths in web content — likely ActiveX/exploit payload");
    }

    // Heavy base64 (> 0.4 normalized) suggests large encoded payloads, not just small data URIs
    if (features[36] > 0.4f) {
        result.strongIndicatorCount++;
        result.strongIndicators.push_back("Large base64 payloads — exceeds normal data URI usage");
    }

    // High byte ratio is ABNORMAL for HTML (should be almost all ASCII)
    if (features[7] > 0.15f) {
        result.strongIndicatorCount++;
        result.strongIndicators.push_back("Non-ASCII byte content in web file — possible embedded binary payload");
    }

    // Determine if we have ONLY weak indicators (= likely false positive)
    result.hasWeakIndicatorsOnly = (result.strongIndicatorCount == 0);

    return result;
}

// ============================================================================
// Indicator Strength Classification
//
// For non-web files: indicators are classified by the feature vector alone.
// For web files: the WebIndicatorAnalysis determines if indicators are "strong"
// (genuinely suspicious) or "weak" (expected for the file type).
// ============================================================================

/// Count strong malicious indicators in a generic (non-web) feature vector.
/// These are indicators that suggest real malicious intent regardless of type.
inline int countStrongIndicators(const std::vector<float>& features)
{
    if (features.size() < 38) return 0;
    int count = 0;

    // Very high entropy (packed/encrypted)
    if (features[1] > 7.5f) count++;

    // PE-specific strong signals
    if (features[16] > 0.5f) {
        if (features[18] > 0.875f)  count++;  // high section entropy
        if (features[20] < 0.5f)    count++;  // EP outside code
        if (features[25] > 0.5f)    count++;  // anomalous section names
        if (features[27] > 0.5f)    count++;  // inflated virtual size
    }

    // Suspicious APIs (process injection, crypto, keylogging)
    if (features[32] > 0.3f) count++;

    // Embedded IPs
    if (features[34] > 0.0f) count++;

    // Registry paths
    if (features[35] > 0.0f) count++;

    return count;
}

// ============================================================================
// Full Classification Logic
//
//   score < effectiveThreshold                              → Clean
//   score >= threshold, weak indicators only (web files)    → Clean (suppressed)
//   score >= threshold, no strong indicators                → Anomalous
//   score >= threshold + some strong indicators             → Suspicious
//   score >= 0.85 + multiple strong indicators              → Critical
// ============================================================================

struct ClassificationResult {
    ClassificationLevel level       = ClassificationLevel::Clean;
    SeverityLevel       severity    = SeverityLevel::Low;   // legacy compat
    float               score       = 0.0f;
    float               threshold   = 0.5f;
    float               effectiveThreshold = 0.5f;
    FileCategory        fileCategory = FileCategory::Unknown;
    int                 strongIndicators = 0;
    int                 weakIndicators   = 0;
    std::vector<std::string> indicators;  // human-readable, strong ones first
    bool                suppressed  = false;  // true if benign web file suppressed the alert
};

inline ClassificationResult classifyFile(
    float score,
    float baseThreshold,
    const std::string& extension,
    const std::vector<float>& features)
{
    ClassificationResult cr;
    cr.score        = score;
    cr.threshold    = baseThreshold;
    cr.fileCategory = categorizeExtension(extension);
    cr.effectiveThreshold = adjustedThreshold(baseThreshold, cr.fileCategory);

    // Below effective threshold → clean
    if (score < cr.effectiveThreshold) {
        cr.level = ClassificationLevel::Clean;
        cr.severity = SeverityLevel::Low;
        return cr;
    }

    // ── Web content: special handling ───────────────────────────────────
    if (cr.fileCategory == FileCategory::WebContent) {
        WebIndicatorAnalysis webAnalysis = analyzeWebIndicators(features);
        cr.strongIndicators = webAnalysis.strongIndicatorCount;
        cr.weakIndicators   = webAnalysis.weakIndicatorCount;
        cr.indicators       = webAnalysis.strongIndicators;
        // Append weak indicators with [EXPECTED] tag
        for (const auto& wi : webAnalysis.weakIndicators)
            cr.indicators.push_back("[EXPECTED] " + wi);

        if (webAnalysis.hasWeakIndicatorsOnly) {
            // Only benign web signals → suppress entirely as Clean
            cr.level = ClassificationLevel::Clean;
            cr.severity = SeverityLevel::Low;
            cr.suppressed = true;
            return cr;
        }

        // Has some strong indicators: classify based on strength
        if (webAnalysis.strongIndicatorCount >= 3 && score >= 0.85f) {
            cr.level = ClassificationLevel::Critical;
            cr.severity = SeverityLevel::Critical;
        } else if (webAnalysis.strongIndicatorCount >= 2) {
            cr.level = ClassificationLevel::Suspicious;
            cr.severity = SeverityLevel::High;
        } else {
            // 1 strong indicator: still just anomalous for web files
            cr.level = ClassificationLevel::Anomalous;
            cr.severity = SeverityLevel::Medium;
        }
        return cr;
    }

    // ── Text/data files: require strong indicators ─────────────────────
    if (cr.fileCategory == FileCategory::TextData) {
        int strong = countStrongIndicators(features);
        cr.strongIndicators = strong;
        if (strong == 0) {
            cr.level = ClassificationLevel::Clean;
            cr.severity = SeverityLevel::Low;
            cr.suppressed = true;
            return cr;
        }
        // Has indicators: use conservative classification
        if (strong >= 3 && score >= 0.85f) {
            cr.level = ClassificationLevel::Suspicious;
            cr.severity = SeverityLevel::High;
        } else {
            cr.level = ClassificationLevel::Anomalous;
            cr.severity = SeverityLevel::Medium;
        }
        return cr;
    }

    // ── Source code, compiled artifacts, build output: very conservative ─
    // These are developer files. Suspicious API names, URLs, base64, registry
    // references are NORMAL in source code (they're the strings being scanned
    // for, not indicators of malice). Require multiple strong indicators.
    if (cr.fileCategory == FileCategory::SourceCode ||
        cr.fileCategory == FileCategory::CompiledArtifact ||
        cr.fileCategory == FileCategory::BuildOutput) {
        int strong = countStrongIndicators(features);
        cr.strongIndicators = strong;
        if (strong <= 1) {
            // 0-1 strong indicators in developer files = Clean (suppressed)
            cr.level = ClassificationLevel::Clean;
            cr.severity = SeverityLevel::Low;
            cr.suppressed = true;
            return cr;
        }
        // 2+ strong indicators: conservative classification
        if (strong >= 4 && score >= 0.90f) {
            cr.level = ClassificationLevel::Suspicious;
            cr.severity = SeverityLevel::High;
        } else {
            cr.level = ClassificationLevel::Anomalous;
            cr.severity = SeverityLevel::Low;
        }
        return cr;
    }

    // ── Archives, Installers, Media: require strong indicators ─────────
    if (cr.fileCategory == FileCategory::Archive ||
        cr.fileCategory == FileCategory::Installer ||
        cr.fileCategory == FileCategory::MediaBinary) {
        int strong = countStrongIndicators(features);
        cr.strongIndicators = strong;
        if (strong == 0) {
            cr.level = ClassificationLevel::Anomalous;
            cr.severity = SeverityLevel::Low;
        } else if (strong >= 2 && score >= 0.80f) {
            cr.level = ClassificationLevel::Suspicious;
            cr.severity = SeverityLevel::High;
        } else {
            cr.level = ClassificationLevel::Anomalous;
            cr.severity = SeverityLevel::Medium;
        }
        return cr;
    }

    // ── PE Binaries + Scripts: model is calibrated, use score-based ────
    int strong = countStrongIndicators(features);
    cr.strongIndicators = strong;

    if (score >= 0.90f && strong >= 2) {
        cr.level = ClassificationLevel::Critical;
        cr.severity = SeverityLevel::Critical;
    } else if (score >= 0.75f && strong >= 1) {
        cr.level = ClassificationLevel::Suspicious;
        cr.severity = SeverityLevel::High;
    } else if (score >= 0.60f || strong >= 1) {
        cr.level = ClassificationLevel::Suspicious;
        cr.severity = SeverityLevel::Medium;
    } else {
        cr.level = ClassificationLevel::Anomalous;
        cr.severity = SeverityLevel::Low;
    }

    return cr;
}

// ============================================================================
// Structured Scan Result
// ============================================================================

struct ScanResult
{
    // --- Detection stage (ONNX model) ---
    std::string           filePath;
    std::string           fileName;
    float                 anomalyScore       = 0.0f;
    float                 threshold          = 0.5f;
    float                 effectiveThreshold = 0.5f;
    ClassificationLevel   classification     = ClassificationLevel::Clean;
    SeverityLevel         severity           = SeverityLevel::Low;
    FileCategory          fileCategory       = FileCategory::Unknown;
    bool                  isSuspicious       = false;
    std::string           fileExtension;

    // Key indicators (top contributing factors)
    std::vector<std::string> keyIndicators;

    // --- Embedded AI explanation (always populated) ---
    std::string              aiSummary;
    std::vector<std::string> recommendedActions;

    // --- LLM explanation (Ollama / Llama3 — empty if unavailable) ---
    std::string              llmExplanation;

    // --- Raw data ---
    std::vector<float> features;
};

// ============================================================================
// Key Indicator Extraction  –  file-type aware
// ============================================================================

inline std::vector<std::string> extractKeyIndicators(
    const std::vector<float>& features,
    FileCategory fileCategory = FileCategory::Unknown,
    int maxIndicators = 4)
{
    if (features.size() < 38)
        return {};

    // For web content, use the specialized analyzer
    if (fileCategory == FileCategory::WebContent) {
        WebIndicatorAnalysis wa = analyzeWebIndicators(features);
        // Return strong indicators first, then weak ones (tagged)
        std::vector<std::string> result;
        for (const auto& si : wa.strongIndicators) {
            if (static_cast<int>(result.size()) >= maxIndicators) break;
            result.push_back(si);
        }
        for (const auto& wi : wa.weakIndicators) {
            if (static_cast<int>(result.size()) >= maxIndicators) break;
            result.push_back("[Expected for web] " + wi);
        }
        if (result.empty())
            result.push_back("Statistical anomaly in byte distribution patterns");
        return result;
    }

    // For all other file types: generic indicator extraction
    struct Indicator {
        float score;
        std::string description;
    };
    std::vector<Indicator> candidates;

    auto fmt = [](float val, int decimals) -> std::string {
        std::ostringstream o;
        o << std::fixed << std::setprecision(decimals) << val;
        return o.str();
    };

    // Entropy
    if (features[1] > 7.0f)
        candidates.push_back({features[1] / 8.0f,
            "Very high Shannon entropy (" + fmt(features[1], 2)
            + "/8.0) — suggests encryption or packing"});
    else if (features[1] > 5.5f)
        candidates.push_back({features[1] / 10.0f,
            "Elevated entropy (" + fmt(features[1], 2)
            + "/8.0) — moderate obfuscation signal"});

    // High byte ratio
    if (features[7] > 0.4f)
        candidates.push_back({features[7],
            "High ratio of non-ASCII bytes (" + fmt(features[7] * 100.0f, 1)
            + "%) — packed or encrypted content"});

    // PE-specific indicators
    if (features[16] > 0.5f) {
        if (features[18] > 0.875f)
            candidates.push_back({features[18],
                "PE section with very high entropy — likely packed/encrypted code"});
        if (features[20] < 0.5f)
            candidates.push_back({0.8f,
                "Entry point outside code section — unusual for legitimate software"});
        if (features[21] < 0.5f)
            candidates.push_back({0.6f,
                "No debug information — stripped binary, common in malware"});
        if (features[25] > 0.5f)
            candidates.push_back({0.7f,
                "Anomalous PE section names — possible packer (UPX, Themida, etc.)"});
        if (features[27] > 0.5f)
            candidates.push_back({features[27],
                "Inflated virtual-to-raw size ratio — unpacking indicator"});
    }

    // Suspicious strings
    if (features[32] > 0.3f)
        candidates.push_back({features[32],
            "Multiple suspicious API references (process injection, crypto, keylogging)"});
    else if (features[32] > 0.1f)
        candidates.push_back({features[32] * 1.5f,
            "Some suspicious API references detected"});

    // Network indicators
    if (features[33] > 0.0f || features[34] > 0.0f)
        candidates.push_back({std::max(features[33], features[34]),
            "Embedded URLs or IP addresses found — possible C2 communication"});

    // Registry paths
    if (features[35] > 0.0f)
        candidates.push_back({features[35],
            "Registry path references — potential persistence mechanism"});

    // Base64 strings
    if (features[36] > 0.0f)
        candidates.push_back({features[36],
            "Base64-encoded strings detected — possible payload obfuscation"});

    // Sort by suspicion score and take top N
    std::sort(candidates.begin(), candidates.end(),
              [](const Indicator& a, const Indicator& b) {
                  return a.score > b.score;
              });

    std::vector<std::string> result;
    int count = std::min(maxIndicators, static_cast<int>(candidates.size()));
    for (int i = 0; i < count; ++i)
        result.push_back(candidates[i].description);

    if (result.empty())
        result.push_back("Statistical anomaly in byte distribution patterns");

    return result;
}

// ============================================================================
// Terminal Output Formatter  –  classification-aware
// ============================================================================

inline std::string formatTerminalOutput(const ScanResult& result)
{
    const char* RESET  = "\033[0m";
    const char* BOLD   = "\033[1m";
    const char* DIM    = "\033[2m";
    const char* WHITE  = "\033[97m";
    const char* CYAN   = "\033[36m";
    const char* GREEN  = "\033[32m";

    const char* clColor = classificationToColor(result.classification);
    const char* clLabel = classificationToLabel(result.classification);

    std::ostringstream ss;

    // Top border
    ss << "\n" << DIM
       << "  ══════════════════════════════════════════════════════════════"
       << RESET << "\n";

    // Status line – uses classification level, NOT always "SUSPICIOUS"
    ss << "  " << clColor << BOLD << clLabel << RESET
       << "  " << DIM << "Engine:" << RESET << " AI Anomaly Detection"
       << "  " << DIM << "(" << fileCategoryToString(result.fileCategory) << ")" << RESET << "\n";

    // Separator
    ss << DIM
       << "  ──────────────────────────────────────────────────────────────"
       << RESET << "\n";

    // File info
    ss << "  " << CYAN << "File:      " << RESET << WHITE << result.fileName << RESET << "\n";
    ss << "  " << CYAN << "Score:     " << RESET
       << clColor << std::fixed << std::setprecision(3) << result.anomalyScore
       << RESET << " / 1.000\n";
    ss << "  " << CYAN << "Threshold: " << RESET
       << std::setprecision(3) << result.threshold;
    if (std::abs(result.effectiveThreshold - result.threshold) > 0.001f) {
        ss << DIM << " (effective: " << result.effectiveThreshold
           << " for ." << result.fileExtension << ")" << RESET;
    }
    ss << "\n";
    ss << "  " << CYAN << "Verdict:   " << RESET
       << clColor << BOLD << classificationToString(result.classification) << RESET << "\n";

    // Key Indicators  [EMBEDDED-AI]
    if (!result.keyIndicators.empty()) {
        ss << "\n  " << BOLD << "[EMBEDDED-AI] Key Indicators:" << RESET << "\n";
        for (const auto& indicator : result.keyIndicators) {
            ss << "    " << DIM << "•" << RESET << " " << indicator << "\n";
        }
    }

    // Embedded AI Summary
    if (!result.aiSummary.empty()) {
        ss << "\n  " << BOLD << "[EMBEDDED-AI] Summary:" << RESET << "\n";
        std::istringstream words(result.aiSummary);
        std::string word;
        int lineLen = 0;
        ss << "    ";
        while (words >> word) {
            if (lineLen + static_cast<int>(word.size()) + 1 > 60 && lineLen > 0) {
                ss << "\n    ";
                lineLen = 0;
            }
            if (lineLen > 0) { ss << " "; lineLen++; }
            ss << word;
            lineLen += static_cast<int>(word.size());
        }
        ss << "\n";
    }

    // Embedded AI Recommended Actions
    if (!result.recommendedActions.empty()) {
        ss << "\n  " << BOLD << "[EMBEDDED-AI] Recommended Actions:" << RESET << "\n";
        for (size_t i = 0; i < result.recommendedActions.size(); ++i) {
            ss << "    " << GREEN << (i + 1) << "." << RESET
               << " " << result.recommendedActions[i] << "\n";
        }
    }

    // LLM Explanation (Ollama / Llama3)  –  separate section
    const char* MAGENTA = "\033[35m";
    if (!result.llmExplanation.empty()) {
        ss << "\n  " << MAGENTA << BOLD << "[LLM] Explanation (Ollama / Llama3):" << RESET << "\n";
        // Word-wrap the LLM response
        std::istringstream llmWords(result.llmExplanation);
        std::string w;
        int ll = 0;
        ss << "    ";
        while (llmWords >> w) {
            if (ll + static_cast<int>(w.size()) + 1 > 60 && ll > 0) {
                ss << "\n    ";
                ll = 0;
            }
            if (ll > 0) { ss << " "; ll++; }
            ss << w;
            ll += static_cast<int>(w.size());
        }
        ss << "\n";
    } else {
        ss << "\n  " << DIM << "[LLM] Explanation unavailable — "
           << "showing embedded AI summary instead" << RESET << "\n";
    }

    // Bottom border
    ss << DIM
       << "  ══════════════════════════════════════════════════════════════"
       << RESET << "\n";

    return ss.str();
}

// ============================================================================
// LLM Response Parser  (unchanged)
// ============================================================================

struct ParsedLLMResponse
{
    std::string summary;
    std::vector<std::string> indicators;
    std::vector<std::string> actions;
};

inline ParsedLLMResponse parseLLMResponse(const std::string& raw)
{
    ParsedLLMResponse parsed;

    enum class Section { None, Summary, Indicators, Actions };
    Section current = Section::None;

    std::istringstream stream(raw);
    std::string line;

    while (std::getline(stream, line)) {
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        line = line.substr(start);
        size_t end = line.find_last_not_of(" \t\r\n");
        if (end != std::string::npos) line = line.substr(0, end + 1);

        std::string upper = line;
        std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

        if (upper.find("SUMMARY:") == 0 || upper.find("SUMMARY") == 0) {
            current = Section::Summary;
            auto colon = line.find(':');
            if (colon != std::string::npos && colon + 1 < line.size()) {
                std::string val = line.substr(colon + 1);
                size_t vs = val.find_first_not_of(" \t");
                if (vs != std::string::npos) parsed.summary = val.substr(vs);
            }
            continue;
        }
        if (upper.find("INDICATORS:") == 0 || upper.find("KEY INDICATORS:") == 0
            || upper.find("INDICATORS") == 0) {
            current = Section::Indicators; continue;
        }
        if (upper.find("ACTIONS:") == 0 || upper.find("RECOMMENDED ACTIONS:") == 0
            || upper.find("ACTIONS") == 0) {
            current = Section::Actions; continue;
        }

        switch (current) {
            case Section::Summary:
                if (!parsed.summary.empty()) parsed.summary += " ";
                parsed.summary += line;
                break;
            case Section::Indicators: {
                std::string cleaned = line;
                if (!cleaned.empty() && (cleaned[0] == '-' || cleaned[0] == '*')) {
                    cleaned = cleaned.substr(1);
                    size_t s = cleaned.find_first_not_of(" \t");
                    if (s != std::string::npos) cleaned = cleaned.substr(s);
                }
                if (!cleaned.empty()) parsed.indicators.push_back(cleaned);
                break;
            }
            case Section::Actions: {
                std::string cleaned = line;
                if (!cleaned.empty() && std::isdigit(cleaned[0])) {
                    auto dot = cleaned.find('.');
                    if (dot != std::string::npos && dot < 3) {
                        cleaned = cleaned.substr(dot + 1);
                        size_t s = cleaned.find_first_not_of(" \t");
                        if (s != std::string::npos) cleaned = cleaned.substr(s);
                    }
                }
                if (!cleaned.empty()) parsed.actions.push_back(cleaned);
                break;
            }
            default:
                if (!line.empty()) {
                    if (!parsed.summary.empty()) parsed.summary += " ";
                    parsed.summary += line;
                }
                break;
        }
    }

    if (parsed.summary.size() > 300) {
        size_t firstPeriod = parsed.summary.find('.');
        if (firstPeriod != std::string::npos) {
            size_t secondPeriod = parsed.summary.find('.', firstPeriod + 1);
            if (secondPeriod != std::string::npos && secondPeriod < 300)
                parsed.summary = parsed.summary.substr(0, secondPeriod + 1);
        }
    }

    return parsed;
}
