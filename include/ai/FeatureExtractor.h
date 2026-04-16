#pragma once
// ============================================================================
// FeatureExtractor.h  –  38-dimensional feature vector for ML anomaly scoring
//
// Features are grouped into four extraction passes:
//   Pass 1 (0-4)   : Metadata + Shannon entropy
//   Pass 2 (5-15)  : Byte-distribution statistics
//   Pass 3 (16-27) : PE (Portable Executable) header analysis
//   Pass 4 (28-37) : String analysis + partial hash features
//
// All features are returned as a flat std::vector<float> of exactly
// kFeatureCount elements.  Missing / not-applicable features are 0.0f.
// ============================================================================

#include <vector>
#include <string>
#include <array>
#include <cstdint>

// Total number of features in the vector
static constexpr int kFeatureCount = 38;

// Human-readable names (useful for CSV headers / debugging)
const char* const kFeatureNames[kFeatureCount] = {
    // --- Pass 1: Metadata + Entropy ---
    "fileSize_log10",          // 0
    "shannonEntropy",          // 1
    "isExecutable",            // 2
    "isScript",                // 3
    "isDLL",                   // 4

    // --- Pass 2: Byte Distribution ---
    "nullByteRatio",           // 5
    "printableAsciiRatio",     // 6
    "highByteRatio",           // 7
    "byteMean",                // 8
    "byteStdDev",              // 9
    "controlCharRatio",        // 10
    "whitespaceRatio",         // 11
    "uniqueByteCount",         // 12  (normalized 0-1)
    "longestNullRun",          // 13  (normalized by file size)
    "entropyFirstQuarter",     // 14
    "entropyLastQuarter",      // 15

    // --- Pass 3: PE Header ---
    "isPE",                    // 16
    "peNumSections",           // 17
    "peMaxSectionEntropy",     // 18
    "peCodeSectionRatio",      // 19
    "peEntryPointInCode",      // 20
    "peHasDebugInfo",          // 21
    "peImportCount",           // 22
    "peExportCount",           // 23
    "peResourceRatio",         // 24
    "peSectionNameAnomaly",    // 25
    "peTimestampAnomaly",      // 26
    "peVirtualSizeRatio",      // 27

    // --- Pass 4: Strings + Hash ---
    "stringCount",             // 28
    "stringDensity",           // 29
    "avgStringLength",         // 30
    "maxStringLength",         // 31
    "suspiciousStringCount",   // 32
    "urlCount",                // 33
    "ipAddressCount",          // 34
    "registryPathCount",       // 35
    "base64StringCount",       // 36
    "hashPartialMatch",        // 37
};

// ============================================================================
// Public API
// ============================================================================

/// Extract the full 38-feature vector from a file on disk.
/// Returns an empty vector on I/O error.
std::vector<float> extractFeatures(const std::string& filePath);

// ============================================================================
// Per-pass helpers (also exposed for unit-testing individual passes)
// ============================================================================

/// Pass 1 – metadata & whole-file Shannon entropy  (features 0-4)
void extractPass1_MetadataEntropy(const std::string& filePath,
                                  const std::vector<uint8_t>& fileBytes,
                                  std::vector<float>& out);

/// Pass 2 – byte-distribution statistics  (features 5-15)
void extractPass2_ByteDistribution(const std::vector<uint8_t>& fileBytes,
                                   std::vector<float>& out);

/// Pass 3 – PE header parsing  (features 16-27)
void extractPass3_PEHeader(const std::vector<uint8_t>& fileBytes,
                           std::vector<float>& out);

/// Pass 4 – string analysis + partial hash match  (features 28-37)
void extractPass4_StringsHash(const std::vector<uint8_t>& fileBytes,
                              std::vector<float>& out);
