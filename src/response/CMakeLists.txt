# =============================================================================
# Odysseus-AI  -  Phase 5: Response & Control Layer
# CMake module for the response subsystem.
#
# Usage from the top-level CMakeLists.txt (once it exists):
#
#     add_subdirectory(src/response)
#     target_link_libraries(odysseus_app PRIVATE odysseus_response)
#
# The library is C++17, has no external dependencies, and is the same on
# macOS and Linux (process kill uses POSIX kill(2)).
# =============================================================================

cmake_minimum_required(VERSION 3.16)
project(odysseus_response CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(odysseus_response STATIC
    ResponseTypes.cpp
    Allowlist.cpp
    Quarantine.cpp
    ActionLog.cpp
    ResponseManager.cpp
)

target_include_directories(odysseus_response
    PUBLIC ${CMAKE_SOURCE_DIR}/include
)

# Pthreads for std::mutex on Linux.
find_package(Threads REQUIRED)
target_link_libraries(odysseus_response PUBLIC Threads::Threads)

# macOS / Linux warnings — strict but pragmatic.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    target_compile_options(odysseus_response PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion)
endif()
