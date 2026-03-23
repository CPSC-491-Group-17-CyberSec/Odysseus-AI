cmake_minimum_required(VERSION 3.20)
project(QtHello LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets Network)

add_executable(main
    src/main.cpp
    src/ui/ui.cpp
    src/ui/MainWindow/MainWindow.cpp
    src/ui/ThreatCard/ThreatCard.cpp
    src/core/FileScanner.cpp
)

target_link_libraries(main PRIVATE Qt6::Widgets Qt6::Network)

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
