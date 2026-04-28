cmake_minimum_required(VERSION 3.20)
project(QtHello LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets Network Charts)

# Copy the malware hash database AND YARA rules next to the executable at build time.
# The data/ tree contains: malware_hashes.txt, yara_rules/, anomaly_model_*.onnx, etc.
file(COPY ${CMAKE_SOURCE_DIR}/data DESTINATION ${CMAKE_BINARY_DIR})

qt_add_resources(APP_RESOURCES resources/resources.qrc)

add_executable(main
    src/main.cpp
    ${APP_RESOURCES}
    src/ui/ui.cpp
    src/ui/MainWindow/MainWindow.cpp
    src/ui/ThreatCard/ThreatCard.cpp
    src/ui/ScanTypeOverlay/ScanTypeOverlay.cpp
    src/ui/SystemStatusPanel/SystemStatusPanel.cpp  # Phase 2 system status panel
    # Phase 4 – UI redesign (Step 1: theme + sidebar shell)
    src/ui/theme/DashboardTheme.cpp
    src/ui/widgets/Sidebar.cpp
    # Phase 4 – Step 2: Dashboard widgets + page
    src/ui/widgets/StatCard.cpp
    src/ui/widgets/DonutChart.cpp
    src/ui/widgets/ScanTypeSelector.cpp
    src/ui/widgets/SecurityScoreCard.cpp
    src/ui/widgets/ActivityList.cpp
    src/ui/pages/DashboardPage.cpp
    # Phase 4 – Step 3: right-slide threat detail panel
    src/ui/widgets/ThreatDetailPanel.cpp
    # Phase 4 – Step 4: settings page + toggle widgets
    src/ui/widgets/ToggleRow.cpp
    src/ui/pages/SettingsPage.cpp
    # Scanner engine – FileScanner.cpp is the AUTOMOC anchor (includes the header
    # so CMake generates moc_FileScanner.cpp). All implementations are in the
    # focused TUs below, compiled with per-file optimization flags.
    src/core/FileScanner.cpp        # AUTOMOC anchor – do not add code here
    src/core/FileScannerContext.cpp # OS/FS detection, filter construction, constructor
    src/core/FileScannerHash.cpp    # hash DB + SHA-256 detection (-O3)
    src/core/FileScannerEngine.cpp  # doScan loop + FileScanner controller (-O2)
    src/core/FileScannerDetectors.cpp  # AI anomaly detection pass
    src/core/FileScannerYaraReputation.cpp  # YARA pass + reputation singletons (Phase 1)
    src/core/ScannerConfig.cpp      # Phase 1.5 – per-feature toggles
    # AI / ML subsystem
    src/ai/FeatureExtractor.cpp    # 38-feature vector extraction (v2/v3)
    src/ai/EmberFeatureExtractor.cpp # 2381-feature EMBER PE extraction (v4)
    src/ai/EmberDetector.cpp       # LightGBM native EMBER inference (v4)
    src/ai/AnomalyDetector.cpp     # ONNX Runtime inference wrapper
    src/ai/LLMExplainer.cpp        # Ollama-based LLM threat explanation
    src/db/ScanDatabase.cpp        # SQLite persistence layer
    src/db/sqlite3.c               # SQLite amalgamation – no install required
    # Phase 1 – YARA + reputation + code signing
    src/scanner/YaraScanner.cpp        # libyara wrapper (3rd detection pass)
    src/reputation/ReputationDB.cpp    # structured local reputation database
    src/reputation/CodeSigning.cpp     # codesign / signature verification
    # Phase 2 – System monitoring
    src/monitor/ProcessEnumerator.cpp  # macOS sysctl + Linux /proc process listing
    src/monitor/PersistenceScanner.cpp # LaunchAgents/Daemons + cron + systemd
    src/monitor/SuspiciousHeuristics.cpp # process-flagging logic
    src/monitor/SystemMonitor.cpp      # orchestrator QObject
    # Header listed explicitly so AUTOMOC scans it (it lives under include/
    # rather than next to the .cpp, which breaks AUTOMOC's same-directory
    # auto-pairing rule).
    include/monitor/SystemMonitor.h
    # Phase 3 – Rootkit awareness (user-space only)
    src/rootkit/ProcessCrossView.cpp        # sysctl ↔ ps PID-set diff
    src/rootkit/KernelExtensionScanner.cpp  # systemextensionsctl + kmutil
    src/rootkit/IntegrityChecker.cpp        # critical-path SHA-256 baseline
    src/rootkit/RootkitMonitor.cpp          # orchestrator (plain namespace)
)

target_include_directories(main PRIVATE
    src/core
    src               # for src/scanner/, src/reputation/, src/db/
    include           # ai/FeatureExtractor.h, ai/AnomalyDetector.h, scanner/, reputation/
)

target_link_libraries(main PRIVATE Qt6::Widgets Qt6::Network Qt6::Charts)

# -----------------------------
# ONNX Runtime (optional – AI anomaly detection)
# -----------------------------
# If ONNX Runtime is installed, find and link it.  If not, the build still
# succeeds: AnomalyDetector.cpp compiles a stub that disables AI scoring.
find_package(onnxruntime QUIET)
if(onnxruntime_FOUND)
    target_link_libraries(main PRIVATE onnxruntime::onnxruntime)
    message(STATUS "ONNX Runtime found – AI anomaly detection enabled")
else()
    # Try pkg-config as fallback
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(ONNXRT QUIET libonnxruntime)
        if(ONNXRT_FOUND)
            target_include_directories(main PRIVATE ${ONNXRT_INCLUDE_DIRS})
            target_link_libraries(main PRIVATE ${ONNXRT_LIBRARIES})
            message(STATUS "ONNX Runtime found via pkg-config – AI anomaly detection enabled")
        endif()
    endif()
    if(NOT ONNXRT_FOUND)
        message(STATUS "ONNX Runtime NOT found – AI anomaly detection will be disabled "
                       "(hash-only mode). Install onnxruntime to enable.")
    endif()
endif()

# -----------------------------
# LightGBM (optional – native EMBER PE detection, ~96.5% accuracy)
# -----------------------------
# If LightGBM is installed, find and link it. If not, the build still
# succeeds: EmberDetector.cpp compiles a stub that falls back to ONNX.
find_package(PkgConfig QUIET)
set(LIGHTGBM_FOUND FALSE)

# Try finding the library directly (Homebrew installs to /opt/homebrew)
find_library(LIGHTGBM_LIBRARY NAMES _lightgbm lib_lightgbm lightgbm
    HINTS /opt/homebrew/lib /usr/local/lib /usr/lib
)
find_path(LIGHTGBM_INCLUDE NAMES lightgbm/c_api.h
    HINTS /opt/homebrew/include /usr/local/include /usr/include
)

if(LIGHTGBM_LIBRARY AND LIGHTGBM_INCLUDE)
    target_include_directories(main PRIVATE ${LIGHTGBM_INCLUDE})
    target_link_libraries(main PRIVATE ${LIGHTGBM_LIBRARY})
    set(LIGHTGBM_FOUND TRUE)
    message(STATUS "LightGBM found – native EMBER PE detection enabled (~96.5% accuracy)")
    message(STATUS "  Library: ${LIGHTGBM_LIBRARY}")
    message(STATUS "  Include: ${LIGHTGBM_INCLUDE}")
else()
    message(STATUS "LightGBM NOT found – will fall back to ONNX-based EMBER detection (~86.5%). "
                   "Install with: brew install lightgbm")
endif()

# -----------------------------
# libyara (optional – YARA rule scanning, Phase 1)
# -----------------------------
# If libyara is installed, find and link it. If not, the build still
# succeeds: YaraScanner.cpp compiles a stub that disables YARA detection
# (the C macro ODY_HAS_YARA gates the real implementation).
#
# macOS (Apple Silicon):  brew install yara          → /opt/homebrew
# macOS (Intel):          brew install yara          → /usr/local
# Linux (Debian/Ubuntu):  sudo apt install libyara-dev
# Linux (Fedora/RHEL):    sudo dnf install yara-devel
set(YARA_FOUND FALSE)

# Try pkg-config first (most reliable)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(YARA QUIET yara)
endif()

if(YARA_FOUND)
    target_include_directories(main PRIVATE ${YARA_INCLUDE_DIRS})
    target_link_libraries(main PRIVATE ${YARA_LIBRARIES})
    target_link_directories(main PRIVATE ${YARA_LIBRARY_DIRS})
    target_compile_definitions(main PRIVATE ODY_HAS_YARA=1)
    message(STATUS "libyara found via pkg-config – YARA rule scanning enabled")
else()
    # Fallback: search common Homebrew/system locations directly
    find_library(YARA_LIBRARY NAMES yara libyara
        HINTS /opt/homebrew/lib /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu
    )
    find_path(YARA_INCLUDE_DIR NAMES yara.h
        HINTS /opt/homebrew/include /usr/local/include /usr/include
    )
    if(YARA_LIBRARY AND YARA_INCLUDE_DIR)
        target_include_directories(main PRIVATE ${YARA_INCLUDE_DIR})
        target_link_libraries(main PRIVATE ${YARA_LIBRARY})
        target_compile_definitions(main PRIVATE ODY_HAS_YARA=1)
        set(YARA_FOUND TRUE)
        message(STATUS "libyara found – YARA rule scanning enabled")
        message(STATUS "  Library: ${YARA_LIBRARY}")
        message(STATUS "  Include: ${YARA_INCLUDE_DIR}")
    else()
        message(STATUS "libyara NOT found – YARA rule scanning will be disabled "
                       "(stub compiled). Install with: brew install yara  (macOS)")
    endif()
endif()

# Per-file optimization flags for the hot scanner paths.
# Applied on top of whatever CMAKE_BUILD_TYPE provides, so Debug builds still
# get optimized scanner code while UI code remains debuggable.
set_source_files_properties(
    src/core/FileScannerHash.cpp
    PROPERTIES COMPILE_OPTIONS "-O3"
)
set_source_files_properties(
    src/core/FileScannerEngine.cpp
    PROPERTIES COMPILE_OPTIONS "-O2"
)

# Suppress warnings on sqlite3.c (third-party file, not our code)
if(MSVC)
    set_source_files_properties(src/db/sqlite3.c PROPERTIES COMPILE_FLAGS "/w")
else()
    set_source_files_properties(src/db/sqlite3.c PROPERTIES COMPILE_FLAGS "-w")
endif()

include(GNUInstallDirs)

# Install the executable
install(TARGETS main
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# -----------------------------
# Qt Deployment for Windows (Qt 6.10)
# -----------------------------
if(WIN32)
    qt_generate_deploy_app_script(
        TARGET main
        OUTPUT_SCRIPT deploy_script
        NO_UNSUPPORTED_PLATFORM_ERROR
    )

    # Run deployment script after install
    install(CODE "
        set(QT_DEPLOY_PREFIX \"${CMAKE_INSTALL_PREFIX}\")
        include(\"${deploy_script}\")
    ")
endif()