// ============================================================================
// FeatureExtractor.cpp  –  38-feature vector extraction for anomaly detection
//
// Four passes over the raw file bytes:
//   Pass 1: metadata + Shannon entropy
//   Pass 2: byte-distribution statistics
//   Pass 3: PE header analysis (lightweight, no external lib)
//   Pass 4: string analysis + partial hash matching
//
// All heavy computation is done on a single read of the file into memory.
// Files > 200 MB are rejected (same cap as the hash scanner).
// ============================================================================

#include "ai/FeatureExtractor.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <fstream>
#include <numeric>
#include <regex>
#include <set>

// ============================================================================
// Helpers
// ============================================================================

/// Shannon entropy of a byte buffer (0.0 – 8.0)
static float shannonEntropy(const uint8_t* data, size_t len) {
  if (len == 0)
    return 0.0f;

  std::array<uint64_t, 256> freq{};
  for (size_t i = 0; i < len; ++i)
    ++freq[data[i]];

  double entropy = 0.0;
  const double dLen = static_cast<double>(len);
  for (int i = 0; i < 256; ++i) {
    if (freq[i] == 0)
      continue;
    double p = static_cast<double>(freq[i]) / dLen;
    entropy -= p * std::log2(p);
  }
  return static_cast<float>(entropy);
}

/// Read the entire file into a byte vector.  Returns empty on failure or
/// if the file exceeds 200 MB.
///
/// Phase 1 reliability fix:
///   The previous version returned `buf` even on partial reads, leaving
///   uninitialized bytes past the read point that the entropy / byte-stat
///   passes interpreted as data. This caused noisy false positives on
///   files that hit a permission boundary mid-read (network mounts,
///   in-flight downloads, files truncated between fstat and read).
///
///   Now we:
///     1. Resize the buffer to exactly the bytes successfully read.
///     2. Return empty if zero bytes read or stream errored.
///     3. Cap at 200 MB the same way the hash pass does.
static std::vector<uint8_t> readFileBytes(const std::string& path) {
  std::ifstream f(path, std::ios::binary | std::ios::ate);
  if (!f.is_open())
    return {};

  const auto size = f.tellg();
  if (size <= 0 || size > 200LL * 1024 * 1024)
    return {};

  std::vector<uint8_t> buf(static_cast<size_t>(size));
  f.seekg(0, std::ios::beg);
  f.read(reinterpret_cast<char*>(buf.data()), size);

  // Number of bytes actually transferred. With ifstream::read this is
  // gcount(); it can be < size on permission errors, truncation, or
  // network-mount failures mid-read.
  const std::streamsize got = f.gcount();
  if (got <= 0)
    return {};                             // nothing read — treat as failure
  if (got < size)
    buf.resize(static_cast<size_t>(got));  // truncate uninit tail
  if (f.bad())
    return {};                             // hard I/O error

  return buf;
}

/// Check file extension (case-insensitive)
static std::string lowerExtension(const std::string& path) {
  auto dot = path.rfind('.');
  if (dot == std::string::npos)
    return "";
  std::string ext = path.substr(dot + 1);
  std::transform(
      ext.begin(), ext.end(), ext.begin(), [](unsigned char c) { return std::tolower(c); });
  return ext;
}

// ============================================================================
// Pass 1 – Metadata + Shannon Entropy  (features 0-4)
// ============================================================================
void extractPass1_MetadataEntropy(
    const std::string& filePath, const std::vector<uint8_t>& fileBytes, std::vector<float>& out) {
  // 0: file size (log10, clamped to avoid log(0))
  double sz = static_cast<double>(fileBytes.size());
  out[0] = (sz > 0) ? static_cast<float>(std::log10(sz)) : 0.0f;

  // 1: whole-file Shannon entropy
  out[1] = shannonEntropy(fileBytes.data(), fileBytes.size());

  // 2-4: type flags based on extension
  std::string ext = lowerExtension(filePath);

  static const std::set<std::string> exeExts = {
      "exe", "com", "scr", "pif", "msi", "elf", "bin", "app", "out"};
  static const std::set<std::string> scriptExts = {
      "bat", "cmd", "ps1", "vbs", "js", "wsh", "wsf", "py", "sh", "bash", "pl", "rb", "php", "hta"};
  static const std::set<std::string> dllExts = {"dll", "sys", "drv", "ocx", "so", "dylib"};

  out[2] = exeExts.count(ext) ? 1.0f : 0.0f;
  out[3] = scriptExts.count(ext) ? 1.0f : 0.0f;
  out[4] = dllExts.count(ext) ? 1.0f : 0.0f;
}

// ============================================================================
// Pass 2 – Byte Distribution  (features 5-15)
// ============================================================================
void extractPass2_ByteDistribution(const std::vector<uint8_t>& fileBytes, std::vector<float>& out) {
  const size_t len = fileBytes.size();
  if (len == 0)
    return;  // features stay 0.0f

  const double dLen = static_cast<double>(len);

  // Build byte frequency histogram
  std::array<uint64_t, 256> freq{};
  for (size_t i = 0; i < len; ++i)
    ++freq[fileBytes[i]];

  // 5: null byte ratio
  out[5] = static_cast<float>(freq[0] / dLen);

  // 6: printable ASCII ratio (0x20 – 0x7E)
  uint64_t printable = 0;
  for (int b = 0x20; b <= 0x7E; ++b)
    printable += freq[b];
  out[6] = static_cast<float>(printable / dLen);

  // 7: high byte ratio (> 0x7F)
  uint64_t high = 0;
  for (int b = 0x80; b <= 0xFF; ++b)
    high += freq[b];
  out[7] = static_cast<float>(high / dLen);

  // 8: byte mean
  double sum = 0.0;
  for (int b = 0; b < 256; ++b)
    sum += static_cast<double>(b) * freq[b];
  double mean = sum / dLen;
  out[8] = static_cast<float>(mean / 255.0);  // normalized 0-1

  // 9: byte standard deviation
  double variance = 0.0;
  for (int b = 0; b < 256; ++b) {
    double diff = static_cast<double>(b) - mean;
    variance += diff * diff * freq[b];
  }
  variance /= dLen;
  out[9] = static_cast<float>(std::sqrt(variance) / 128.0);  // normalized ~0-1

  // 10: control character ratio (0x01-0x1F, excluding tab/LF/CR)
  uint64_t ctrl = 0;
  for (int b = 0x01; b <= 0x1F; ++b) {
    if (b == 0x09 || b == 0x0A || b == 0x0D)
      continue;  // skip tab, LF, CR
    ctrl += freq[b];
  }
  out[10] = static_cast<float>(ctrl / dLen);

  // 11: whitespace ratio (space, tab, LF, CR)
  uint64_t ws = freq[0x20] + freq[0x09] + freq[0x0A] + freq[0x0D];
  out[11] = static_cast<float>(ws / dLen);

  // 12: unique byte count (normalized 0-1)
  int unique = 0;
  for (int b = 0; b < 256; ++b)
    if (freq[b] > 0)
      ++unique;
  out[12] = static_cast<float>(unique / 256.0);

  // 13: longest null run (normalized by file size)
  uint64_t maxNullRun = 0, curNullRun = 0;
  for (size_t i = 0; i < len; ++i) {
    if (fileBytes[i] == 0x00) {
      ++curNullRun;
      if (curNullRun > maxNullRun)
        maxNullRun = curNullRun;
    } else {
      curNullRun = 0;
    }
  }
  out[13] = static_cast<float>(static_cast<double>(maxNullRun) / dLen);

  // 14: entropy of first quarter
  size_t q1End = len / 4;
  if (q1End > 0)
    out[14] = shannonEntropy(fileBytes.data(), q1End);

  // 15: entropy of last quarter
  size_t q4Start = len - (len / 4);
  if (q4Start < len)
    out[15] = shannonEntropy(fileBytes.data() + q4Start, len - q4Start);
}

// ============================================================================
// Pass 3 – PE Header Analysis  (features 16-27)
//
// Lightweight manual parsing of MZ → PE signature → COFF → optional header
// → section table.  No external dependencies.
// ============================================================================

// Helper: read little-endian integers from a byte buffer
static uint16_t readU16(const uint8_t* p) {
  return p[0] | (p[1] << 8);
}
static uint32_t readU32(const uint8_t* p) {
  return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

void extractPass3_PEHeader(const std::vector<uint8_t>& fileBytes, std::vector<float>& out) {
  const size_t len = fileBytes.size();
  const uint8_t* d = fileBytes.data();

  // Minimum PE file: MZ header (64 bytes) + PE sig (4) + COFF (20)
  if (len < 64)
    return;

  // Check MZ signature
  if (d[0] != 'M' || d[1] != 'Z')
    return;

  // e_lfanew at offset 0x3C
  uint32_t peOffset = readU32(d + 0x3C);
  if (peOffset + 24 > len)
    return;

  // Check PE\0\0 signature
  if (d[peOffset] != 'P' || d[peOffset + 1] != 'E' || d[peOffset + 2] != 0 || d[peOffset + 3] != 0)
    return;

  // ---------- We have a valid PE ----------
  out[16] = 1.0f;  // isPE

  const uint8_t* coff = d + peOffset + 4;
  // COFF header: 20 bytes
  // uint16_t machine        = readU16(coff + 0);
  uint16_t numSections = readU16(coff + 2);
  uint32_t timeDateStamp = readU32(coff + 4);
  // uint32_t symTablePtr    = readU32(coff + 8);
  // uint32_t numSymbols     = readU32(coff + 12);
  uint16_t optHeaderSize = readU16(coff + 16);
  uint16_t characteristics = readU16(coff + 18);

  // 17: number of sections (normalized, typical PE has 3-8)
  out[17] = static_cast<float>(numSections) / 16.0f;

  // Determine if 64-bit (PE32+)
  const uint8_t* opt = coff + 20;
  if (static_cast<size_t>(opt - d) + 2 > len)
    return;
  uint16_t magic = readU16(opt);
  bool is64 = (magic == 0x020B);  // PE32+ magic

  // Optional header fields (offsets differ for PE32 vs PE32+)
  uint32_t entryPointRVA = 0;
  uint32_t numDataDirs = 0;
  size_t dataDirOffset = 0;

  if (is64 && static_cast<size_t>(opt - d) + 112 <= len) {
    entryPointRVA = readU32(opt + 16);
    numDataDirs = readU32(opt + 108);
    dataDirOffset = 112;
  } else if (!is64 && static_cast<size_t>(opt - d) + 96 <= len) {
    entryPointRVA = readU32(opt + 16);
    numDataDirs = readU32(opt + 92);
    dataDirOffset = 96;
  }

  // Parse data directories for import/export/debug/resource counts
  uint32_t exportDirRVA = 0, exportDirSize = 0;
  uint32_t importDirRVA = 0, importDirSize = 0;
  uint32_t resourceDirRVA = 0, resourceDirSize = 0;
  uint32_t debugDirRVA = 0, debugDirSize = 0;

  if (numDataDirs > 0 && dataDirOffset > 0) {
    const uint8_t* dd = opt + dataDirOffset;
    size_t ddBase = static_cast<size_t>(dd - d);

    // Each data dir entry = 8 bytes (RVA + Size)
    // Index 0: Export, 1: Import, 2: Resource, 6: Debug
    if (numDataDirs > 0 && ddBase + 8 <= len) {
      exportDirRVA = readU32(dd + 0);
      exportDirSize = readU32(dd + 4);
    }
    if (numDataDirs > 1 && ddBase + 16 <= len) {
      importDirRVA = readU32(dd + 8);
      importDirSize = readU32(dd + 12);
    }
    if (numDataDirs > 2 && ddBase + 24 <= len) {
      resourceDirRVA = readU32(dd + 16);
      resourceDirSize = readU32(dd + 20);
    }
    if (numDataDirs > 6 && ddBase + 56 <= len) {
      debugDirRVA = readU32(dd + 48);
      debugDirSize = readU32(dd + 52);
    }
  }

  // 21: debug info present
  out[21] = (debugDirRVA != 0 && debugDirSize != 0) ? 1.0f : 0.0f;

  // 22: import count estimate (importDirSize / 20 bytes per import descriptor)
  if (importDirSize > 0)
    out[22] = static_cast<float>(importDirSize / 20) / 100.0f;  // normalized

  // 23: export count (rough: exportDirSize implies exported functions)
  out[23] = (exportDirRVA != 0 && exportDirSize > 0) ? 1.0f : 0.0f;

  // 24: resource section ratio
  out[24] = (len > 0) ? static_cast<float>(resourceDirSize) / static_cast<float>(len) : 0.0f;

  // Parse section table
  const uint8_t* secTable = opt + optHeaderSize;
  size_t secTableOff = static_cast<size_t>(secTable - d);

  float maxSectEntropy = 0.0f;
  float codeSectRatio = 0.0f;
  bool epInCode = false;
  bool sectionNameAnomaly = false;
  float maxVirtRawRatio = 0.0f;

  // Known legit section names
  static const std::set<std::string> knownNames = {
      ".text",
      ".rdata",
      ".data",
      ".rsrc",
      ".reloc",
      ".bss",
      ".idata",
      ".edata",
      ".pdata",
      ".tls",
      ".debug",
      ".CRT",
      ".sxdata",
      ".gfids",
      ".00cfg",
      "CODE",
      "DATA",
      ".code"};

  for (int s = 0; s < numSections; ++s) {
    size_t off = secTableOff + s * 40;
    if (off + 40 > len)
      break;

    const uint8_t* sec = d + off;

    // Section name (8 bytes, may not be null-terminated)
    char name[9] = {};
    std::memcpy(name, sec, 8);
    std::string sName(name);

    uint32_t virtualSize = readU32(sec + 8);
    uint32_t virtualAddr = readU32(sec + 12);
    uint32_t rawSize = readU32(sec + 16);
    uint32_t rawOffset = readU32(sec + 20);
    uint32_t sCharacteristics = readU32(sec + 36);

    // Section entropy
    if (rawOffset > 0 && rawSize > 0 && rawOffset + rawSize <= len) {
      float se = shannonEntropy(d + rawOffset, rawSize);
      if (se > maxSectEntropy)
        maxSectEntropy = se;
    }

    // Code section detection (IMAGE_SCN_CNT_CODE = 0x00000020)
    bool isCode = (sCharacteristics & 0x00000020) != 0;
    if (isCode) {
      codeSectRatio = static_cast<float>(rawSize) / static_cast<float>(len);
      // Check if entry point falls within this section's VA range
      if (entryPointRVA >= virtualAddr && entryPointRVA < virtualAddr + virtualSize)
        epInCode = true;
    }

    // Section name anomaly: not in the known set
    if (!sName.empty() && knownNames.find(sName) == knownNames.end()) {
      // Many packers use names like "UPX0", ".ndata", random strings
      sectionNameAnomaly = true;
    }

    // Virtual-to-raw size ratio (inflated virtual size = possible unpacking)
    if (rawSize > 0) {
      float ratio = static_cast<float>(virtualSize) / static_cast<float>(rawSize);
      if (ratio > maxVirtRawRatio)
        maxVirtRawRatio = ratio;
    }
  }

  out[18] = maxSectEntropy / 8.0f;  // normalized 0-1
  out[19] = codeSectRatio;
  out[20] = epInCode ? 1.0f : 0.0f;
  out[25] = sectionNameAnomaly ? 1.0f : 0.0f;

  // 26: timestamp anomaly (before 1990 or after 2030 = suspicious)
  if (timeDateStamp > 0) {
    // Unix timestamp for 1990-01-01 = 631152000, 2030-01-01 = 1893456000
    out[26] = (timeDateStamp < 631152000 || timeDateStamp > 1893456000) ? 1.0f : 0.0f;
  }

  // 27: max virtual/raw ratio (capped and normalized)
  out[27] = std::min(maxVirtRawRatio / 10.0f, 1.0f);
}

// ============================================================================
// Pass 4 – String Analysis + Partial Hash  (features 28-37)
// ============================================================================

/// Extract printable ASCII strings of length >= 4 from raw bytes
static std::vector<std::string> extractStrings(const uint8_t* data, size_t len, int minLen = 4) {
  std::vector<std::string> result;
  std::string current;
  current.reserve(128);

  for (size_t i = 0; i < len; ++i) {
    uint8_t b = data[i];
    if (b >= 0x20 && b <= 0x7E) {
      current.push_back(static_cast<char>(b));
    } else {
      if (static_cast<int>(current.size()) >= minLen)
        result.push_back(std::move(current));
      current.clear();
    }
  }
  if (static_cast<int>(current.size()) >= minLen)
    result.push_back(std::move(current));

  return result;
}

void extractPass4_StringsHash(const std::vector<uint8_t>& fileBytes, std::vector<float>& out) {
  const size_t len = fileBytes.size();
  if (len == 0)
    return;

  auto strings = extractStrings(fileBytes.data(), len);

  // 28: string count (log-scaled)
  out[28] = strings.empty()
                ? 0.0f
                : static_cast<float>(std::log10(static_cast<double>(strings.size()) + 1.0));

  // 29: string density (total string bytes / file size)
  size_t totalStrBytes = 0;
  for (const auto& s : strings)
    totalStrBytes += s.size();
  out[29] = static_cast<float>(static_cast<double>(totalStrBytes) / static_cast<double>(len));

  // 30: average string length (normalized)
  if (!strings.empty()) {
    double avg = static_cast<double>(totalStrBytes) / strings.size();
    out[30] = static_cast<float>(std::min(avg / 100.0, 1.0));
  }

  // 31: max string length (normalized)
  size_t maxLen = 0;
  for (const auto& s : strings)
    if (s.size() > maxLen)
      maxLen = s.size();
  out[31] = static_cast<float>(std::min(static_cast<double>(maxLen) / 500.0, 1.0));

  // Suspicious strings commonly found in malware
  static const std::vector<std::string> suspiciousKeywords = {
      "cmd.exe",
      "powershell",
      "CreateRemoteThread",
      "VirtualAlloc",
      "WriteProcessMemory",
      "NtUnmapViewOfSection",
      "IsDebuggerPresent",
      "GetProcAddress",
      "LoadLibrary",
      "WinExec",
      "ShellExecute",
      "URLDownloadToFile",
      "InternetOpen",
      "HttpSendRequest",
      "RegSetValue",
      "RegCreateKey",
      "CreateService",
      "StartService",
      "OpenProcess",
      "ReadProcessMemory",
      "AdjustTokenPrivileges",
      "LookupPrivilegeValue",
      "CryptEncrypt",
      "CryptDecrypt",
      "BitBlt",
      "keybd_event",
      "GetAsyncKeyState",
      "SetWindowsHookEx",
      "FindWindow",
      "EnumProcesses",
      "Process32First",
      "CreateToolhelp32Snapshot"};

  int suspCount = 0, urlCount = 0, ipCount = 0, regCount = 0, b64Count = 0;

  for (const auto& s : strings) {
    // 32: suspicious keywords
    for (const auto& kw : suspiciousKeywords) {
      if (s.find(kw) != std::string::npos) {
        ++suspCount;
        break;  // count each string once even if multiple keywords match
      }
    }

    // 33: URL patterns (http:// or https://)
    if (s.find("http://") != std::string::npos || s.find("https://") != std::string::npos)
      ++urlCount;

    // 34: IP address pattern (simplified: N.N.N.N where N is 1-3 digits)
    // Look for a simple pattern like digits.digits.digits.digits
    {
      bool foundIP = false;
      for (size_t i = 0; i + 6 < s.size() && !foundIP; ++i) {
        if (std::isdigit(s[i])) {
          int dots = 0;
          size_t j = i;
          while (j < s.size() && (std::isdigit(s[j]) || s[j] == '.')) {
            if (s[j] == '.')
              ++dots;
            ++j;
          }
          if (dots == 3 && j - i >= 7)
            foundIP = true;
        }
      }
      if (foundIP)
        ++ipCount;
    }

    // 35: registry paths
    if (s.find("HKEY_") != std::string::npos || s.find("HKLM\\") != std::string::npos ||
        s.find("HKCU\\") != std::string::npos || s.find("SOFTWARE\\") != std::string::npos ||
        s.find("CurrentVersion\\Run") != std::string::npos)
      ++regCount;

    // 36: base64-like strings (long strings with base64 alphabet, len > 20)
    if (s.size() > 20) {
      bool maybeB64 = true;
      int alphaCount = 0;
      for (char c : s) {
        if (std::isalnum(c) || c == '+' || c == '/' || c == '=')
          ++alphaCount;
      }
      // If >90% of chars match base64 alphabet, flag it
      if (static_cast<double>(alphaCount) / s.size() > 0.90 && s.size() > 40)
        ++b64Count;
    }
  }

  out[32] = static_cast<float>(std::min(suspCount / 10.0, 1.0));
  out[33] = static_cast<float>(std::min(urlCount / 5.0, 1.0));
  out[34] = static_cast<float>(std::min(ipCount / 5.0, 1.0));
  out[35] = static_cast<float>(std::min(regCount / 5.0, 1.0));
  out[36] = static_cast<float>(std::min(b64Count / 5.0, 1.0));

  // 37: hash partial match – placeholder; this will be populated by
  // AnomalyDetector when it has access to the hash DB.  Set 0 here.
  out[37] = 0.0f;
}

// ============================================================================
// Main entry point – runs all 4 passes
// ============================================================================
std::vector<float> extractFeatures(const std::string& filePath) {
  std::vector<uint8_t> fileBytes = readFileBytes(filePath);
  if (fileBytes.empty())
    return {};  // I/O error or file too large

  std::vector<float> features(kFeatureCount, 0.0f);

  extractPass1_MetadataEntropy(filePath, fileBytes, features);
  extractPass2_ByteDistribution(fileBytes, features);
  extractPass3_PEHeader(fileBytes, features);
  extractPass4_StringsHash(fileBytes, features);

  return features;
}
