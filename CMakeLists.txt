cmake_minimum_required(VERSION 3.16)
project(GHCore LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(GHCore INTERFACE)

# Include path
target_include_directories(GHCore INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/Include
)

# Compile definitions
target_compile_definitions(GHCore INTERFACE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# Windows dependency
target_link_libraries(GHCore INTERFACE
    psapi
)

# Build examples
add_subdirectory(examples)