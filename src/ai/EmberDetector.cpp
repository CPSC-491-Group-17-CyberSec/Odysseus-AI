// ============================================================================
// EmberDetector.cpp  –  LightGBM C API inference for EMBER PE detection
//
// Loads a LightGBM model (native text format) and a scaler (binary format),
// then scores 2381-feature EMBER vectors with the full gradient-boosted
// tree ensemble (~96.5% accuracy on EMBER-2018-v2).
//
// Falls back gracefully if LightGBM is not available at build time.
// ============================================================================

#include "ai/EmberDetector.h"
#include "ai/EmberFeatureExtractor.h"

// Guard LightGBM include — if not available, compile a stub.
#if __has_include(<lightgbm/c_api.h>)
    #define HAS_LIGHTGBM 1
    #include <lightgbm/c_api.h>
#else
    #define HAS_LIGHTGBM 0
#endif

#include <fstream>
#include <iostream>
#include <cstring>
#include <vector>
#include <cmath>

static constexpr int EMBER_FEATURES = 2381;

// ============================================================================
// PImpl
// ============================================================================
struct EmberDetector::Impl
{
#if HAS_LIGHTGBM
    BoosterHandle booster = nullptr;
#endif
    // Scaler parameters (loaded from ember_scaler.bin)
    std::vector<double> mean;
    std::vector<double> scale;
    bool loaded = false;
};

// ============================================================================
// Constructor / Destructor
// ============================================================================
EmberDetector::EmberDetector()
    : m_impl(std::make_unique<Impl>())
{}

EmberDetector::~EmberDetector()
{
#if HAS_LIGHTGBM
    if (m_impl && m_impl->booster) {
        LGBM_BoosterFree(m_impl->booster);
        m_impl->booster = nullptr;
    }
#endif
}

// ============================================================================
// load
// ============================================================================
bool EmberDetector::load(const std::string& modelPath, const std::string& scalerPath)
{
#if HAS_LIGHTGBM
    // ── Load scaler ────────────────────────────────────────────────────
    {
        std::ifstream f(scalerPath, std::ios::binary);
        if (!f.is_open()) {
            std::cerr << "[EmberDetector] Cannot open scaler: " << scalerPath << std::endl;
            return false;
        }

        uint32_t nFeatures = 0;
        f.read(reinterpret_cast<char*>(&nFeatures), sizeof(nFeatures));
        if (static_cast<int>(nFeatures) != EMBER_FEATURES) {
            std::cerr << "[EmberDetector] Scaler feature count mismatch: "
                      << nFeatures << " vs " << EMBER_FEATURES << std::endl;
            return false;
        }

        m_impl->mean.resize(EMBER_FEATURES);
        m_impl->scale.resize(EMBER_FEATURES);
        f.read(reinterpret_cast<char*>(m_impl->mean.data()),
               EMBER_FEATURES * sizeof(double));
        f.read(reinterpret_cast<char*>(m_impl->scale.data()),
               EMBER_FEATURES * sizeof(double));

        if (!f.good()) {
            std::cerr << "[EmberDetector] Scaler file truncated" << std::endl;
            return false;
        }

        std::cout << "[EmberDetector] Scaler loaded: " << scalerPath << std::endl;
    }

    // ── Load LightGBM model ────────────────────────────────────────────
    {
        int numIterations = 0;
        int ret = LGBM_BoosterCreateFromModelfile(
            modelPath.c_str(), &numIterations, &m_impl->booster);

        if (ret != 0) {
            std::cerr << "[EmberDetector] LightGBM load failed: "
                      << LGBM_GetLastError() << std::endl;
            return false;
        }

        std::cout << "[EmberDetector] LightGBM model loaded: " << modelPath
                  << " (" << numIterations << " iterations)" << std::endl;
    }

    m_impl->loaded = true;
    return true;

#else
    (void)modelPath;
    (void)scalerPath;
    std::cerr << "[EmberDetector] LightGBM not available at build time." << std::endl;
    return false;
#endif
}

bool EmberDetector::isLoaded() const
{
    return m_impl && m_impl->loaded;
}

// ============================================================================
// score  –  scale features + run LightGBM inference
// ============================================================================
float EmberDetector::score(const std::vector<float>& rawFeatures) const
{
#if HAS_LIGHTGBM
    if (!m_impl->loaded || !m_impl->booster)
        return -1.0f;

    if (static_cast<int>(rawFeatures.size()) != EMBER_FEATURES)
        return -1.0f;

    // Scale the feature vector
    std::vector<double> scaled(EMBER_FEATURES);
    for (int i = 0; i < EMBER_FEATURES; ++i) {
        const double s = m_impl->scale[i];
        scaled[i] = (s > 1e-10)
            ? (static_cast<double>(rawFeatures[i]) - m_impl->mean[i]) / s
            : 0.0;
    }

    // Run LightGBM prediction
    int64_t outLen = 0;
    double result = 0.0;

    int ret = LGBM_BoosterPredictForMatSingleRow(
        m_impl->booster,
        scaled.data(),
        C_API_DTYPE_FLOAT64,
        EMBER_FEATURES,
        1,  // is_row_major
        C_API_PREDICT_NORMAL,
        0,  // start_iteration
        -1, // num_iteration (-1 = all)
        "",  // parameter (empty = use training params)
        &outLen,
        &result);

    if (ret != 0) {
        std::cerr << "[EmberDetector] Prediction error: "
                  << LGBM_GetLastError() << std::endl;
        return -1.0f;
    }

    // LightGBM binary classifier returns P(class=1) directly
    return static_cast<float>(std::clamp(result, 0.0, 1.0));

#else
    (void)rawFeatures;
    return -1.0f;
#endif
}

// ============================================================================
// scoreFile  –  convenience wrapper
// ============================================================================
float EmberDetector::scoreFile(const std::string& filePath) const
{
    auto features = extractEmberFeatures(filePath);
    if (features.empty())
        return -1.0f;
    return score(features);
}
