#pragma once
// ============================================================================
// EmberFeatureExtractor.h  –  2381-dimensional EMBER feature vector for PE files
//
// Extracts the same feature groups as the EMBER (Endgame Malware BEnchmark
// for Research) library, producing a 2381-element float vector compatible
// with the v4 ONNX model trained on EMBER-2018-v2 data.
//
// Feature groups and their dimensions:
//   ByteHistogram          [0..255]        256 features
//   ByteEntropyHistogram   [256..511]      256 features
//   StringExtractor        [512..615]      104 features
//   GeneralFileInfo        [616..625]       10 features
//   HeaderFileInfo         [626..687]       62 features
//   SectionInfo            [688..942]      255 features
//   ImportsInfo            [943..2222]    1280 features
//   ExportsInfo            [2223..2350]    128 features
//   DataDirectories        [2351..2380]     30 features
//                                  TOTAL: 2381
//
// Only PE files should be passed to this extractor.  Non-PE files will
// produce a zero vector (which the model will classify as benign).
//
// Thread safety: fully reentrant — no shared mutable state.
// ============================================================================

#include <vector>
#include <string>
#include <cstdint>

/// Total EMBER feature vector dimensionality.
static constexpr int kEmberFeatureCount = 2381;

/// Extract the 2381-dimensional EMBER feature vector from a PE file.
/// Returns an empty vector on I/O error or if the file is not a PE.
std::vector<float> extractEmberFeatures(const std::string& filePath);

/// Extract EMBER features from already-loaded file bytes.
/// Returns an empty vector if the bytes don't start with a valid PE header.
std::vector<float> extractEmberFeatures(const std::vector<uint8_t>& fileBytes);

/// Quick check: does this file look like a PE (MZ header)?
bool isPEFile(const std::vector<uint8_t>& fileBytes);
