cmake_minimum_required(VERSION 3.20)
project(QtHello LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets Network)

# Copy the malware hash database next to the executable at build time
file(COPY ${CMAKE_SOURCE_DIR}/data DESTINATION ${CMAKE_BINARY_DIR})

add_executable(main
    src/main.cpp
    src/ui/ui.cpp
    src/ui/MainWindow/MainWindow.cpp
    src/ui/ThreatCard/ThreatCard.cpp
    src/ui/ScanTypeOverlay/ScanTypeOverlay.cpp
    # Scanner engine – FileScanner.cpp is the AUTOMOC anchor (includes the header
    # so CMake generates moc_FileScanner.cpp). All implementations are in the
    # focused TUs below, compiled with per-file optimization flags.
    src/core/FileScanner.cpp        # AUTOMOC anchor – do not add code here
    src/core/FileScannerContext.cpp # OS/FS detection, filter construction, constructor
    src/core/FileScannerHash.cpp    # hash DB + SHA-256 detection (-O3)
    src/core/FileScannerEngine.cpp  # doScan loop + FileScanner controller (-O2)
    # FileScannerDetectors.cpp is excluded – reserved for future detectors
    src/db/ScanDatabase.cpp       # SQLite persistence layer
    src/db/sqlite3.c              # SQLite amalgamation – no install required
)

target_include_directories(main PRIVATE src/core)

target_link_libraries(main PRIVATE Qt6::Widgets Qt6::Network)

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