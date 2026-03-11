cmake_minimum_required(VERSION 3.16)
project(GHCore CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(GHCORE_HEADERS
    src/GHCore.hpp
    src/Memory/Memory.hpp
    src/Memory/Scan.hpp
    src/Process/Process.hpp
    src/Hooks/VmtHook.hpp
    src/Hooks/DetourHook.hpp
    src/Hooks/IatHook.hpp
    src/Inject/Inject.hpp
    src/Utils/Utils.hpp
)

add_library(GHCore INTERFACE)

target_sources(GHCore INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/GHCore.hpp>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/Memory/Memory.hpp>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/Memory/Scan.hpp>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/Process/Process.hpp>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/Hooks/VmtHook.hpp>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/Hooks/DetourHook.hpp>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/Hooks/IatHook.hpp>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/Inject/Inject.hpp>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/Utils/Utils.hpp>
)

target_include_directories(GHCore INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:include>
)

target_compile_definitions(GHCore INTERFACE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(GHCore INTERFACE psapi)

option(GHCORE_BUILD_EXAMPLE "Build example" ON)
if(GHCORE_BUILD_EXAMPLE)
    add_executable(GHCore_Example src/example/main.cpp)
    target_link_libraries(GHCore_Example PRIVATE GHCore)
endif()
