#pragma once
// ============================================================================
// FileTypeScoring.h  –  Per-file-type scoring, calibration, and classification
//
// PHASE 2: Medium-term improvement to the detection pipeline.
//
// Problems solved:
//   1. The ONNX model was trained on PE executables.  A raw score of 0.72
//      means very different things for an .exe vs. an .html file.
//   2. Feature importance varies wildly by type: PE section entropy matters
//      for executables but is irrelevant (always 0) for HTML.
//   3. A single threshold + bump was too coarse — we need per-type
//      calibration curves that map raw scores to normalized risk scores.
//
// Architecture:
//
//   ┌──────────────────┐     ┌─────────────────────┐
//   │  Raw Features     │     │ FileTypeProfile      │
//   │  (38-dim vector)  │────>│  • featureWeights[]  │
//   └──────────────────┘     │  • calibration curve  │
//                            │  • indicator config   │
//                            └──────────┬────────────┘
//                                       │
//                            ┌──────────▼────────────┐
//                            │  calibrateScore()      │
//                            │  raw → normalized      │
//                            └──────────┬────────────┘
//                                       │
//                            ┌──────────▼────────────┐
//                            │  classifyCalibrated()  │
//                            │  normalized → verdict  │
//                            └───────────────────────┘
//
// The old classifyFile() in ScanResultFormatter.h is preserved for backward
// compatibility but callers should prefer the new pipeline.
// ============================================================================

#include "ai/ScanResultFormatter.h"
#include <string>
#include <vector>
#include <array>
#include <cmath>
#include <algorithm>
#include <sstream>
#include <iomanip>

// ============================================================================
// Feature Weight Profile  –  per-type relevance weights for the 38 features
//
// A weight of 0.0 means the feature is irrelevant for this file type.
// A weight of 1.0 means the feature is at standard importance.
// A weight > 1.0 means the feature is extra-important for this type.
//
// These weights are applied as a post-hoc adjustment to the ONNX score
// by computing a weighted indicator strength score that modulates the
// raw ML output.
// ============================================================================

struct FeatureWeightProfile {
    // 38 weights, one per feature index. Default = 1.0 (no adjustment).
    std::array<float, 38> weights;

    // How much the weighted indicator score modulates the raw ML score.
    // 0.0 = trust raw score entirely, 1.0 = trust weighted indicators entirely.
    // Typical: 0.3 for PE (model is calibrated), 0.6 for HTML (model is not).
    float indicatorBlendFactor = 0.3f;

    FeatureWeightProfile() { weights.fill(1.0f); }
};

// ============================================================================
// Calibration Curve  –  maps raw ONNX score to normalized risk score
//
// The model outputs ~0.5 for mildly anomalous PE files and ~0.9 for truly
// malicious ones.  But for HTML files, even benign pages score 0.6-0.8
// because of structural features (entropy, URLs, base64) the model
// was never trained to expect.
//
// Per-type calibration uses a piecewise linear mapping:
//   rawScore → normalizedScore via control points.
//
// Example for WebContent:
//   raw 0.0-0.80 → normalized 0.0-0.20  (most HTML is noise below 0.80)
//   raw 0.80-0.95 → normalized 0.20-0.60 (genuinely anomalous range)
//   raw 0.95-1.0  → normalized 0.60-1.0  (very suspicious)
// ============================================================================

struct CalibrationPoint {
    float rawScore;
    float normalizedScore;
};

struct CalibrationCurve {
    // Sorted by rawScore, ascending.  Must have at least 2 points.
    std::vector<CalibrationPoint> points;

    /// Apply the piecewise linear calibration.
    float calibrate(float rawScore) const
    {
        if (points.size() < 2) return rawScore;  // fallback: identity

        // Clamp to curve bounds
        if (rawScore <= points.front().rawScore)
            return points.front().normalizedScore;
        if (rawScore >= points.back().rawScore)
            return points.back().normalizedScore;

        // Find the segment
        for (size_t i = 1; i < points.size(); ++i) {
            if (rawScore <= points[i].rawScore) {
                const auto& lo = points[i - 1];
                const auto& hi = points[i];
                float t = (rawScore - lo.rawScore) / (hi.rawScore - lo.rawScore);
                return lo.normalizedScore + t * (hi.normalizedScore - lo.normalizedScore);
            }
        }
        return points.back().normalizedScore;
    }
};

// ============================================================================
// Indicator Thresholds  –  per-type tuning for what counts as "strong"
//
// Different file types have different baselines for what's normal.
// E.g., entropy of 6.5 is suspicious for a .txt but normal for a .zip.
// ============================================================================

struct IndicatorThresholds {
    float entropyStrong        = 7.2f;   // above this = strong indicator
    float entropyWeak          = 5.5f;   // above this = weak indicator
    float highByteRatioStrong  = 0.15f;  // non-ASCII bytes
    float suspiciousApiStrong  = 0.2f;   // features[32]
    float urlDensityStrong     = 0.6f;   // features[33]
    float ipAddressStrong      = 0.2f;   // features[34]
    float registryPathStrong   = 0.0f;   // features[35] (any = strong)
    float base64Strong         = 0.4f;   // features[36]
    float printableAsciiLow    = 0.5f;   // below this = strong for text types
};

// ============================================================================
// FileTypeProfile  –  the complete scoring profile for a file category
// ============================================================================

struct FileTypeProfile {
    FileCategory       category;
    FeatureWeightProfile weights;
    CalibrationCurve   calibration;
    IndicatorThresholds thresholds;

    // Classification thresholds on the CALIBRATED (not raw) score
    float cleanCeiling     = 0.40f;  // below this = Clean
    float anomalousCeiling = 0.65f;  // below this = Anomalous
    float suspiciousCeiling= 0.85f;  // below this = Suspicious; above = Critical

    // Minimum strong indicators required for each classification level.
    // minStrongForAnomalous: prevents statistical noise from generating findings
    // when no concrete malicious signal is present.
    int minStrongForAnomalous  = 1;   // default: at least one concrete indicator
    int minStrongForSuspicious = 1;
    int minStrongForCritical   = 2;
};

// ============================================================================
// Built-in Profiles
// ============================================================================

namespace FileTypeProfiles {

/// PE Binaries (.exe, .dll, .sys)  –  model was trained on these
inline FileTypeProfile PEBinary()
{
    FileTypeProfile p;
    p.category = FileCategory::PEBinary;

    // Weights: PE features are at full importance
    p.weights.weights.fill(1.0f);
    // Boost PE-specific features
    p.weights.weights[16] = 1.2f;  // isPE
    p.weights.weights[18] = 1.3f;  // peMaxSectionEntropy
    p.weights.weights[20] = 1.2f;  // peEntryPointInCode
    p.weights.weights[25] = 1.1f;  // peSectionNameAnomaly
    p.weights.weights[27] = 1.1f;  // peVirtualSizeRatio
    p.weights.weights[32] = 1.3f;  // suspiciousStringCount
    p.weights.indicatorBlendFactor = 0.25f;  // mostly trust the model

    // Calibration: nearly identity — model is calibrated for PE
    p.calibration.points = {
        {0.0f, 0.0f},
        {0.50f, 0.45f},
        {0.70f, 0.65f},
        {0.85f, 0.82f},
        {1.0f, 1.0f}
    };

    // Thresholds: standard
    p.thresholds.entropyStrong       = 7.5f;
    p.thresholds.entropyWeak         = 6.0f;
    p.thresholds.highByteRatioStrong = 0.40f;
    p.thresholds.suspiciousApiStrong = 0.3f;

    // Classification — raised: PE model is well-calibrated, require real signal
    p.cleanCeiling         = 0.50f;
    p.anomalousCeiling     = 0.70f;
    p.suspiciousCeiling    = 0.88f;
    p.minStrongForAnomalous  = 1;
    p.minStrongForSuspicious = 1;
    p.minStrongForCritical   = 2;

    return p;
}

/// Scripts (.bat, .ps1, .vbs, .py, .sh)
inline FileTypeProfile Script()
{
    FileTypeProfile p;
    p.category = FileCategory::Script;

    p.weights.weights.fill(1.0f);
    // PE features are irrelevant for scripts
    for (int i = 16; i <= 27; ++i)
        p.weights.weights[i] = 0.0f;
    // String analysis is very important for scripts
    p.weights.weights[28] = 1.2f;  // stringCount
    p.weights.weights[32] = 1.5f;  // suspiciousStringCount
    p.weights.weights[33] = 1.2f;  // urlCount
    p.weights.weights[36] = 1.3f;  // base64StringCount
    p.weights.indicatorBlendFactor = 0.40f;

    // Calibration: slight compression — scripts score a bit high
    p.calibration.points = {
        {0.0f, 0.0f},
        {0.55f, 0.30f},
        {0.70f, 0.50f},
        {0.85f, 0.75f},
        {1.0f, 1.0f}
    };

    p.thresholds.entropyStrong       = 7.0f;
    p.thresholds.entropyWeak         = 5.0f;
    p.thresholds.suspiciousApiStrong = 0.2f;
    p.thresholds.base64Strong        = 0.3f;

    p.cleanCeiling         = 0.45f;
    p.anomalousCeiling     = 0.68f;
    p.suspiciousCeiling    = 0.85f;
    p.minStrongForAnomalous  = 1;
    p.minStrongForSuspicious = 1;
    p.minStrongForCritical   = 2;

    return p;
}

/// Web Content (.html, .htm, .css, .js, .svg)
inline FileTypeProfile WebContent()
{
    FileTypeProfile p;
    p.category = FileCategory::WebContent;

    p.weights.weights.fill(1.0f);
    // PE features are completely irrelevant
    for (int i = 16; i <= 27; ++i)
        p.weights.weights[i] = 0.0f;
    // Downweight features that are EXPECTED in HTML
    p.weights.weights[1]  = 0.3f;  // entropy — moderate entropy is normal
    p.weights.weights[6]  = 0.1f;  // printableAsciiRatio — always high, not useful
    p.weights.weights[33] = 0.2f;  // urlCount — URLs are normal in HTML
    p.weights.weights[36] = 0.3f;  // base64StringCount — data URIs are normal
    // Boost features that are genuinely suspicious in HTML
    p.weights.weights[7]  = 1.5f;  // highByteRatio — abnormal for text
    p.weights.weights[32] = 1.8f;  // suspiciousStringCount — APIs don't belong in HTML
    p.weights.weights[34] = 1.5f;  // ipAddressCount — suspicious in HTML
    p.weights.weights[35] = 2.0f;  // registryPathCount — very suspicious in HTML
    p.weights.indicatorBlendFactor = 0.60f;  // heavily trust indicators over raw score

    // Calibration: AGGRESSIVE compression — HTML files score falsely high
    p.calibration.points = {
        {0.0f,  0.0f},
        {0.60f, 0.05f},   // raw 0.60 → almost nothing
        {0.80f, 0.20f},   // raw 0.80 → mild anomaly
        {0.90f, 0.45f},   // raw 0.90 → moderate
        {0.95f, 0.70f},   // raw 0.95 → suspicious
        {1.0f,  1.0f}
    };

    // Indicator thresholds: tighter for HTML
    p.thresholds.entropyStrong       = 7.2f;   // very high for text
    p.thresholds.entropyWeak         = 5.0f;
    p.thresholds.highByteRatioStrong = 0.15f;  // any non-ASCII is odd for HTML
    p.thresholds.suspiciousApiStrong = 0.2f;
    p.thresholds.urlDensityStrong    = 0.6f;
    p.thresholds.base64Strong        = 0.4f;   // large payloads (not small data URIs)
    p.thresholds.printableAsciiLow   = 0.5f;

    // Classification: conservative — need strong evidence for HTML
    p.cleanCeiling         = 0.42f;
    p.anomalousCeiling     = 0.68f;
    p.suspiciousCeiling    = 0.85f;
    p.minStrongForAnomalous  = 2;
    p.minStrongForSuspicious = 2;
    p.minStrongForCritical   = 3;

    return p;
}

/// Text/Data (.txt, .json, .xml, .csv, .log, .ini)
inline FileTypeProfile TextData()
{
    FileTypeProfile p;
    p.category = FileCategory::TextData;

    p.weights.weights.fill(1.0f);
    for (int i = 16; i <= 27; ++i)
        p.weights.weights[i] = 0.0f;  // PE irrelevant
    p.weights.weights[1]  = 0.5f;  // entropy — text files can be varied
    p.weights.weights[6]  = 0.2f;  // printable ASCII — expected high
    p.weights.weights[33] = 0.4f;  // URLs can appear in config files
    p.weights.weights[32] = 1.5f;  // suspicious APIs are alarming in text
    p.weights.weights[35] = 1.8f;  // registry paths are alarming
    p.weights.indicatorBlendFactor = 0.55f;

    // Calibration: heavy compression — text files often score high falsely
    p.calibration.points = {
        {0.0f,  0.0f},
        {0.65f, 0.05f},
        {0.80f, 0.15f},
        {0.90f, 0.40f},
        {0.95f, 0.65f},
        {1.0f,  1.0f}
    };

    p.thresholds.entropyStrong       = 7.0f;
    p.thresholds.entropyWeak         = 4.5f;
    p.thresholds.highByteRatioStrong = 0.10f;  // any non-ASCII is suspect in text
    p.thresholds.suspiciousApiStrong = 0.15f;

    p.cleanCeiling         = 0.42f;
    p.anomalousCeiling     = 0.65f;
    p.suspiciousCeiling    = 0.82f;
    p.minStrongForAnomalous  = 2;
    p.minStrongForSuspicious = 2;
    p.minStrongForCritical   = 3;

    return p;
}

/// Archives (.zip, .gz, .7z, .rar, .tar)
inline FileTypeProfile Archive()
{
    FileTypeProfile p;
    p.category = FileCategory::Archive;

    p.weights.weights.fill(1.0f);
    for (int i = 16; i <= 27; ++i)
        p.weights.weights[i] = 0.0f;  // PE irrelevant
    // Archives have naturally high entropy — downweight
    p.weights.weights[1]  = 0.2f;
    p.weights.weights[7]  = 0.3f;  // high byte ratio is expected for compressed data
    p.weights.weights[12] = 0.2f;  // unique byte count — always high for archives
    // String features matter more (embedded strings in archives = suspicious)
    p.weights.weights[32] = 1.5f;
    p.weights.weights[33] = 1.3f;
    p.weights.weights[34] = 1.5f;
    p.weights.weights[35] = 1.8f;
    p.weights.indicatorBlendFactor = 0.50f;

    // Calibration: compressed data inflates raw scores
    p.calibration.points = {
        {0.0f,  0.0f},
        {0.70f, 0.10f},
        {0.85f, 0.30f},
        {0.92f, 0.55f},
        {0.97f, 0.80f},
        {1.0f,  1.0f}
    };

    p.thresholds.entropyStrong       = 7.95f;  // archives are ~8.0 normally
    p.thresholds.entropyWeak         = 7.5f;
    p.thresholds.highByteRatioStrong = 0.60f;  // expected for compressed data

    p.cleanCeiling         = 0.42f;
    p.anomalousCeiling     = 0.68f;
    p.suspiciousCeiling    = 0.85f;
    p.minStrongForAnomalous  = 2;
    p.minStrongForSuspicious = 2;
    p.minStrongForCritical   = 3;

    return p;
}

/// Installers (.dmg, .pkg, .msi, .deb, .rpm)
inline FileTypeProfile Installer()
{
    FileTypeProfile p;
    p.category = FileCategory::Installer;

    p.weights.weights.fill(1.0f);
    // Installers can have PE-like structure inside — keep PE weights moderate
    for (int i = 16; i <= 27; ++i)
        p.weights.weights[i] = 0.6f;
    p.weights.weights[1]  = 0.4f;  // high entropy expected
    p.weights.weights[7]  = 0.4f;  // mixed content expected
    p.weights.weights[32] = 1.3f;
    p.weights.weights[34] = 1.3f;
    p.weights.weights[35] = 1.5f;
    p.weights.indicatorBlendFactor = 0.45f;

    p.calibration.points = {
        {0.0f,  0.0f},
        {0.65f, 0.10f},
        {0.80f, 0.30f},
        {0.90f, 0.55f},
        {0.95f, 0.80f},
        {1.0f,  1.0f}
    };

    p.thresholds.entropyStrong       = 7.8f;
    p.thresholds.entropyWeak         = 6.5f;
    p.thresholds.highByteRatioStrong = 0.50f;

    p.cleanCeiling         = 0.42f;
    p.anomalousCeiling     = 0.68f;
    p.suspiciousCeiling    = 0.85f;
    p.minStrongForAnomalous  = 2;
    p.minStrongForSuspicious = 2;
    p.minStrongForCritical   = 3;

    return p;
}

/// Media/Document binaries (.jpg, .png, .mp3, .pdf, .docx)
inline FileTypeProfile MediaBinary()
{
    FileTypeProfile p;
    p.category = FileCategory::MediaBinary;

    p.weights.weights.fill(1.0f);
    for (int i = 16; i <= 27; ++i)
        p.weights.weights[i] = 0.0f;
    p.weights.weights[1]  = 0.3f;  // high entropy is normal for compressed media
    p.weights.weights[7]  = 0.2f;  // high bytes are normal
    p.weights.weights[12] = 0.2f;  // byte diversity is expected
    // Suspicious strings in media are VERY alarming
    p.weights.weights[32] = 2.0f;
    p.weights.weights[34] = 1.8f;
    p.weights.weights[35] = 2.0f;
    p.weights.indicatorBlendFactor = 0.55f;

    p.calibration.points = {
        {0.0f,  0.0f},
        {0.70f, 0.05f},
        {0.85f, 0.25f},
        {0.93f, 0.55f},
        {0.97f, 0.80f},
        {1.0f,  1.0f}
    };

    p.thresholds.entropyStrong       = 7.9f;
    p.thresholds.entropyWeak         = 7.0f;
    p.thresholds.highByteRatioStrong = 0.70f;

    p.cleanCeiling         = 0.42f;
    p.anomalousCeiling     = 0.68f;
    p.suspiciousCeiling    = 0.85f;
    p.minStrongForAnomalous  = 2;
    p.minStrongForSuspicious = 2;
    p.minStrongForCritical   = 3;

    return p;
}

/// Source Code (.cpp, .h, .c, .java, .rs, .go, .swift)
/// Developer source files commonly contain security-related keywords,
/// API names, URLs, base64 examples, registry paths — all NORMAL for code.
inline FileTypeProfile SourceCode()
{
    FileTypeProfile p;
    p.category = FileCategory::SourceCode;

    p.weights.weights.fill(1.0f);
    // PE features are irrelevant
    for (int i = 16; i <= 27; ++i)
        p.weights.weights[i] = 0.0f;
    // Heavily downweight features that are EXPECTED in source code
    p.weights.weights[1]  = 0.3f;   // entropy — varied in source
    p.weights.weights[6]  = 0.1f;   // printable ASCII — always high
    p.weights.weights[28] = 0.2f;   // stringCount — source is full of strings
    p.weights.weights[32] = 0.1f;   // suspiciousStringCount — API names are normal in code!
    p.weights.weights[33] = 0.2f;   // urlCount — normal in code
    p.weights.weights[34] = 0.3f;   // ipAddressCount — can be test data
    p.weights.weights[35] = 0.2f;   // registryPathCount — normal in security code
    p.weights.weights[36] = 0.2f;   // base64StringCount — test data, examples
    // Only high byte ratio is genuinely alarming in source
    p.weights.weights[7]  = 1.5f;   // binary content in a source file is unusual
    p.weights.indicatorBlendFactor = 0.65f;  // heavily trust indicators over raw score

    // Calibration: very aggressive compression — source files are always benign-ish
    p.calibration.points = {
        {0.0f,  0.0f},
        {0.60f, 0.03f},
        {0.80f, 0.10f},
        {0.90f, 0.25f},
        {0.95f, 0.50f},
        {1.0f,  1.0f}
    };

    p.thresholds.entropyStrong       = 7.5f;   // very high bar for source
    p.thresholds.entropyWeak         = 6.0f;
    p.thresholds.highByteRatioStrong = 0.10f;   // binary in source = alarming
    p.thresholds.suspiciousApiStrong = 0.5f;    // high bar: source talks about APIs
    p.thresholds.base64Strong        = 0.6f;    // high bar: examples are normal

    // Classification: very conservative — source code is nearly always benign
    p.cleanCeiling         = 0.42f;
    p.anomalousCeiling     = 0.68f;
    p.suspiciousCeiling    = 0.85f;
    p.minStrongForAnomalous  = 3;
    p.minStrongForSuspicious = 3;
    p.minStrongForCritical   = 4;

    return p;
}

/// Compiled Artifacts (.o, .obj, .pyc, .class)
/// Object files have high entropy, non-ASCII bytes — all normal.
inline FileTypeProfile CompiledArtifact()
{
    FileTypeProfile p;
    p.category = FileCategory::CompiledArtifact;

    p.weights.weights.fill(1.0f);
    // PE features: partially relevant (object files can have sections)
    for (int i = 16; i <= 27; ++i)
        p.weights.weights[i] = 0.3f;
    // High entropy and non-ASCII are completely expected
    p.weights.weights[1]  = 0.1f;   // entropy: always high
    p.weights.weights[7]  = 0.1f;   // high byte ratio: always high
    p.weights.weights[12] = 0.1f;   // unique byte count: always high
    // Strings in object files can contain anything from the source
    p.weights.weights[32] = 0.15f;  // suspiciousStrings: inherited from source
    p.weights.weights[33] = 0.2f;   // urls: can be in string tables
    p.weights.weights[35] = 0.2f;   // registry: can be in string tables
    p.weights.weights[36] = 0.2f;   // base64: can be in string tables
    p.weights.indicatorBlendFactor = 0.60f;

    // Calibration: very aggressive — compiled artifacts always score high
    p.calibration.points = {
        {0.0f,  0.0f},
        {0.70f, 0.05f},
        {0.85f, 0.15f},
        {0.93f, 0.35f},
        {0.97f, 0.60f},
        {1.0f,  1.0f}
    };

    p.thresholds.entropyStrong       = 7.95f;  // same as archives
    p.thresholds.entropyWeak         = 7.0f;
    p.thresholds.highByteRatioStrong = 0.70f;  // very high: expected for binary
    p.thresholds.suspiciousApiStrong = 0.4f;

    p.cleanCeiling         = 0.42f;
    p.anomalousCeiling     = 0.68f;
    p.suspiciousCeiling    = 0.85f;
    p.minStrongForAnomalous  = 3;
    p.minStrongForSuspicious = 3;
    p.minStrongForCritical   = 4;

    return p;
}

/// Build Output (Makefile, CMakeLists.txt, *.cmake, *.pro)
/// Build config files are text-like but can reference paths, URLs, etc.
inline FileTypeProfile BuildOutput()
{
    FileTypeProfile p;
    p.category = FileCategory::BuildOutput;

    p.weights.weights.fill(1.0f);
    for (int i = 16; i <= 27; ++i)
        p.weights.weights[i] = 0.0f;  // PE irrelevant
    // Build files naturally contain paths, URLs, and package names
    p.weights.weights[1]  = 0.3f;
    p.weights.weights[6]  = 0.1f;
    p.weights.weights[32] = 0.1f;   // "suspicious" strings = package names
    p.weights.weights[33] = 0.1f;   // URLs = package repositories
    p.weights.weights[34] = 0.2f;   // IPs = CI server addresses
    p.weights.weights[35] = 0.1f;   // registry paths = build configuration
    p.weights.weights[36] = 0.2f;   // base64 = encoded tokens, hashes
    p.weights.indicatorBlendFactor = 0.65f;

    p.calibration.points = {
        {0.0f,  0.0f},
        {0.65f, 0.03f},
        {0.80f, 0.08f},
        {0.90f, 0.20f},
        {0.95f, 0.45f},
        {1.0f,  1.0f}
    };

    p.thresholds.entropyStrong       = 7.0f;
    p.thresholds.entropyWeak         = 5.0f;
    p.thresholds.highByteRatioStrong = 0.10f;
    p.thresholds.suspiciousApiStrong = 0.5f;

    p.cleanCeiling         = 0.42f;
    p.anomalousCeiling     = 0.68f;
    p.suspiciousCeiling    = 0.85f;
    p.minStrongForAnomalous  = 3;
    p.minStrongForSuspicious = 3;
    p.minStrongForCritical   = 4;

    return p;
}

/// Unknown file types  –  moderate defaults
inline FileTypeProfile Unknown()
{
    FileTypeProfile p;
    p.category = FileCategory::Unknown;

    p.weights.weights.fill(1.0f);
    p.weights.indicatorBlendFactor = 0.35f;

    p.calibration.points = {
        {0.0f,  0.0f},
        {0.55f, 0.35f},
        {0.75f, 0.60f},
        {0.90f, 0.82f},
        {1.0f,  1.0f}
    };

    p.cleanCeiling         = 0.47f;
    p.anomalousCeiling     = 0.70f;
    p.suspiciousCeiling    = 0.87f;
    p.minStrongForAnomalous  = 1;
    p.minStrongForSuspicious = 1;
    p.minStrongForCritical   = 2;

    return p;
}

/// Look up the profile for a given FileCategory.
inline const FileTypeProfile& getProfile(FileCategory cat)
{
    // Static profiles — constructed once
    static const FileTypeProfile profiles[] = {
        PEBinary(),          // 0
        Script(),            // 1
        WebContent(),        // 2
        TextData(),          // 3
        Archive(),           // 4
        Installer(),         // 5
        MediaBinary(),       // 6
        Unknown(),           // 7
        SourceCode(),        // 8
        CompiledArtifact(),  // 9
        BuildOutput()        // 10
    };

    switch (cat) {
        case FileCategory::PEBinary:          return profiles[0];
        case FileCategory::Script:            return profiles[1];
        case FileCategory::WebContent:        return profiles[2];
        case FileCategory::TextData:          return profiles[3];
        case FileCategory::Archive:           return profiles[4];
        case FileCategory::Installer:         return profiles[5];
        case FileCategory::MediaBinary:       return profiles[6];
        case FileCategory::Unknown:           return profiles[7];
        case FileCategory::SourceCode:        return profiles[8];
        case FileCategory::CompiledArtifact:  return profiles[9];
        case FileCategory::BuildOutput:       return profiles[10];
    }
    return profiles[7];
}

}  // namespace FileTypeProfiles

// ============================================================================
// Weighted Indicator Scoring
//
// Computes a normalized "indicator strength" score by evaluating features
// against the type-specific thresholds and weights.
//
// Returns a value in [0.0, 1.0] where:
//   0.0 = no relevant indicators
//   1.0 = every indicator is maximally triggered
// ============================================================================

struct WeightedIndicatorResult {
    float score           = 0.0f;   // normalized 0–1
    int   strongCount     = 0;
    int   weakCount       = 0;
    std::vector<std::string> strongIndicators;
    std::vector<std::string> weakIndicators;
};

inline WeightedIndicatorResult computeWeightedIndicators(
    const std::vector<float>& features,
    const FileTypeProfile& profile)
{
    WeightedIndicatorResult result;
    if (features.size() < 38) return result;

    const auto& w = profile.weights.weights;
    const auto& t = profile.thresholds;

    float totalWeight = 0.0f;
    float triggeredWeight = 0.0f;

    auto fmt = [](float val, int decimals) -> std::string {
        std::ostringstream o;
        o << std::fixed << std::setprecision(decimals) << val;
        return o.str();
    };

    // ── Entropy ────────────────────────────────────────────────────────
    if (w[1] > 0.01f) {
        totalWeight += w[1];
        if (features[1] > t.entropyStrong) {
            triggeredWeight += w[1];
            result.strongCount++;
            result.strongIndicators.push_back(
                "Very high entropy (" + fmt(features[1], 2) + "/8.0) for this file type");
        } else if (features[1] > t.entropyWeak) {
            triggeredWeight += w[1] * 0.3f;
            result.weakCount++;
            result.weakIndicators.push_back(
                "Elevated entropy (" + fmt(features[1], 2) + "/8.0)");
        }
    }

    // ── Printable ASCII (low = suspicious for text-like types) ─────────
    if (w[6] > 0.01f) {
        totalWeight += w[6];
        if (features[6] < t.printableAsciiLow) {
            triggeredWeight += w[6];
            result.strongCount++;
            result.strongIndicators.push_back(
                "Low printable ASCII ratio (" + fmt(features[6] * 100.0f, 1)
                + "%) — unusual for this file type");
        }
    }

    // ── High byte ratio ────────────────────────────────────────────────
    if (w[7] > 0.01f) {
        totalWeight += w[7];
        if (features[7] > t.highByteRatioStrong) {
            triggeredWeight += w[7];
            result.strongCount++;
            result.strongIndicators.push_back(
                "High non-ASCII byte ratio (" + fmt(features[7] * 100.0f, 1)
                + "%) — possible binary payload");
        }
    }

    // ── PE-specific features (only if weights are nonzero) ─────────────
    if (w[16] > 0.01f && features[16] > 0.5f) {
        totalWeight += w[18] + w[20] + w[25] + w[27];

        if (features[18] > 0.875f && w[18] > 0.01f) {
            triggeredWeight += w[18];
            result.strongCount++;
            result.strongIndicators.push_back(
                "PE section with very high entropy — likely packed/encrypted");
        }
        if (features[20] < 0.5f && w[20] > 0.01f) {
            triggeredWeight += w[20];
            result.strongCount++;
            result.strongIndicators.push_back(
                "Entry point outside code section");
        }
        if (features[25] > 0.5f && w[25] > 0.01f) {
            triggeredWeight += w[25];
            result.strongCount++;
            result.strongIndicators.push_back(
                "Anomalous PE section names — possible packer");
        }
        if (features[27] > 0.5f && w[27] > 0.01f) {
            triggeredWeight += w[27];
            result.strongCount++;
            result.strongIndicators.push_back(
                "Inflated virtual-to-raw size ratio");
        }
    }

    // ── Suspicious API references ──────────────────────────────────────
    if (w[32] > 0.01f) {
        totalWeight += w[32];
        if (features[32] > t.suspiciousApiStrong) {
            triggeredWeight += w[32];
            result.strongCount++;
            result.strongIndicators.push_back(
                "Suspicious API references (process injection, crypto, keylogging)");
        } else if (features[32] > t.suspiciousApiStrong * 0.5f) {
            triggeredWeight += w[32] * 0.3f;
            result.weakCount++;
            result.weakIndicators.push_back(
                "Some API references detected");
        }
    }

    // ── URL density ────────────────────────────────────────────────────
    if (w[33] > 0.01f) {
        totalWeight += w[33];
        if (features[33] > t.urlDensityStrong) {
            triggeredWeight += w[33];
            result.strongCount++;
            result.strongIndicators.push_back(
                "High URL density — possible phishing or redirect chain");
        } else if (features[33] > 0.0f) {
            triggeredWeight += w[33] * 0.15f;
            result.weakCount++;
            result.weakIndicators.push_back("Contains embedded URLs");
        }
    }

    // ── IP addresses ───────────────────────────────────────────────────
    if (w[34] > 0.01f) {
        totalWeight += w[34];
        if (features[34] > t.ipAddressStrong) {
            triggeredWeight += w[34];
            result.strongCount++;
            result.strongIndicators.push_back(
                "Multiple embedded IP addresses — possible C2 beaconing");
        } else if (features[34] > 0.0f) {
            triggeredWeight += w[34] * 0.3f;
            result.weakCount++;
            result.weakIndicators.push_back("Contains embedded IP address(es)");
        }
    }

    // ── Registry paths ─────────────────────────────────────────────────
    if (w[35] > 0.01f) {
        totalWeight += w[35];
        if (features[35] > t.registryPathStrong) {
            triggeredWeight += w[35];
            result.strongCount++;
            result.strongIndicators.push_back(
                "Registry path references — potential persistence mechanism");
        }
    }

    // ── Base64 strings ─────────────────────────────────────────────────
    if (w[36] > 0.01f) {
        totalWeight += w[36];
        if (features[36] > t.base64Strong) {
            triggeredWeight += w[36];
            result.strongCount++;
            result.strongIndicators.push_back(
                "Large base64 payloads — possible obfuscated content");
        } else if (features[36] > 0.0f) {
            triggeredWeight += w[36] * 0.15f;
            result.weakCount++;
            result.weakIndicators.push_back("Contains base64 strings");
        }
    }

    // Normalize
    if (totalWeight > 0.0f)
        result.score = std::min(triggeredWeight / totalWeight, 1.0f);

    return result;
}

// ============================================================================
// Calibrated Classification  –  the Phase 2 replacement for classifyFile()
//
// Pipeline:
//   1. Look up FileTypeProfile for the file's category
//   2. Calibrate the raw ONNX score through the type's calibration curve
//   3. Compute weighted indicator strength score
//   4. Blend: finalScore = (1-blend)*calibratedScore + blend*indicatorScore
//   5. Classify using the type's threshold ceilings + indicator counts
//
// This produces much better results than Phase 1's flat threshold bumps
// because each file type has its own score-to-risk mapping.
// ============================================================================

inline ClassificationResult classifyFileCalibrated(
    float rawScore,
    float baseThreshold,
    const std::string& extension,
    const std::vector<float>& features)
{
    ClassificationResult cr;
    cr.score     = rawScore;
    cr.threshold = baseThreshold;
    cr.fileCategory = categorizeExtension(extension);

    const FileTypeProfile& profile = FileTypeProfiles::getProfile(cr.fileCategory);

    // Step 1: Calibrate the raw score
    float calibrated = profile.calibration.calibrate(rawScore);

    // Step 2: Compute weighted indicator strength
    WeightedIndicatorResult indicators = computeWeightedIndicators(features, profile);
    cr.strongIndicators = indicators.strongCount;
    cr.weakIndicators   = indicators.weakCount;

    // Merge indicator descriptions
    cr.indicators = indicators.strongIndicators;
    for (const auto& wi : indicators.weakIndicators)
        cr.indicators.push_back("[Expected] " + wi);

    // Step 3: Blend calibrated score with indicator score
    float blend = profile.weights.indicatorBlendFactor;
    float finalScore = (1.0f - blend) * calibrated + blend * indicators.score;

    // Store the effective threshold for display (the calibrated clean ceiling)
    cr.effectiveThreshold = profile.cleanCeiling;

    // Step 4: Classify using the type's thresholds + indicator requirements

    // ── Special handling for web content: suppress weak-only signals ────
    if (cr.fileCategory == FileCategory::WebContent &&
        indicators.strongCount == 0)
    {
        // Web files with ONLY weak indicators are never flagged, regardless of score
        cr.level = ClassificationLevel::Clean;
        cr.severity = SeverityLevel::Low;
        cr.suppressed = true;
        return cr;
    }

    // ── Special handling for developer files: suppress unless very strong ─
    if (cr.fileCategory == FileCategory::SourceCode ||
        cr.fileCategory == FileCategory::CompiledArtifact ||
        cr.fileCategory == FileCategory::BuildOutput)
    {
        if (indicators.strongCount <= 1) {
            // Developer files with 0-1 strong indicators: suppress as Clean
            cr.level = ClassificationLevel::Clean;
            cr.severity = SeverityLevel::Low;
            cr.suppressed = true;
            return cr;
        }
    }

    // ── Below clean ceiling → Clean ────────────────────────────────────
    if (finalScore < profile.cleanCeiling) {
        cr.level = ClassificationLevel::Clean;
        cr.severity = SeverityLevel::Low;
        return cr;
    }

    // ── Critical: high score + sufficient strong indicators ────────────
    if (finalScore >= profile.suspiciousCeiling &&
        indicators.strongCount >= profile.minStrongForCritical)
    {
        cr.level = ClassificationLevel::Critical;
        cr.severity = SeverityLevel::Critical;
        return cr;
    }

    // ── Suspicious: moderate+ score + sufficient strong indicators ─────
    if (finalScore >= profile.anomalousCeiling &&
        indicators.strongCount >= profile.minStrongForSuspicious)
    {
        cr.level = ClassificationLevel::Suspicious;
        cr.severity = SeverityLevel::High;
        return cr;
    }

    // ── Anomalous: above clean ceiling, but require minStrongForAnomalous.
    // Without a concrete indicator, statistical noise alone is not enough
    // to file a finding — suppress as Clean.
    if (indicators.strongCount < profile.minStrongForAnomalous) {
        cr.level = ClassificationLevel::Clean;
        cr.severity = SeverityLevel::Low;
        cr.suppressed = true;
        return cr;
    }

    cr.level = ClassificationLevel::Anomalous;
    cr.severity = (finalScore >= profile.anomalousCeiling)
                  ? SeverityLevel::Medium
                  : SeverityLevel::Low;

    return cr;
}

// ============================================================================
// Debug helper: dump the full calibration pipeline for a single file
// (useful for tuning profiles — call from tests or CLI flags)
// ============================================================================

inline std::string debugScoringPipeline(
    float rawScore,
    float baseThreshold,
    const std::string& extension,
    const std::vector<float>& features)
{
    FileCategory cat = categorizeExtension(extension);
    const FileTypeProfile& profile = FileTypeProfiles::getProfile(cat);

    float calibrated = profile.calibration.calibrate(rawScore);
    WeightedIndicatorResult indicators = computeWeightedIndicators(features, profile);
    float blend = profile.weights.indicatorBlendFactor;
    float finalScore = (1.0f - blend) * calibrated + blend * indicators.score;

    ClassificationResult cr = classifyFileCalibrated(rawScore, baseThreshold, extension, features);

    std::ostringstream ss;
    ss << std::fixed << std::setprecision(3);
    ss << "=== Scoring Pipeline Debug ===\n"
       << "Extension:      ." << extension << "\n"
       << "Category:       " << fileCategoryToString(cat) << "\n"
       << "Raw Score:      " << rawScore << "\n"
       << "Calibrated:     " << calibrated << "\n"
       << "Indicator Score:" << indicators.score << "\n"
       << "Blend Factor:   " << blend << "\n"
       << "Final Score:    " << finalScore << "\n"
       << "Strong Indicators: " << indicators.strongCount << "\n"
       << "Weak Indicators:   " << indicators.weakCount << "\n"
       << "Thresholds: Clean < " << profile.cleanCeiling
       << " < Anomalous < " << profile.anomalousCeiling
       << " < Suspicious < " << profile.suspiciousCeiling
       << " < Critical\n"
       << "Min strong for Suspicious: " << profile.minStrongForSuspicious << "\n"
       << "Min strong for Critical:   " << profile.minStrongForCritical << "\n"
       << "VERDICT:        " << classificationToString(cr.level) << "\n";

    if (!indicators.strongIndicators.empty()) {
        ss << "\nStrong Indicators:\n";
        for (const auto& s : indicators.strongIndicators)
            ss << "  [!] " << s << "\n";
    }
    if (!indicators.weakIndicators.empty()) {
        ss << "Weak Indicators:\n";
        for (const auto& w : indicators.weakIndicators)
            ss << "  [~] " << w << "\n";
    }

    return ss.str();
}
