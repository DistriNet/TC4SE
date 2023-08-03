# Minimum CMake version to be able to CMake this project
cmake_minimum_required(VERSION 3.21)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ATTENTION:
# Set Intel API Key by uncommenting the code below. Register and get the API key from Intel at:
# https://api.portal.trustedservices.intel.com/provisioning-certification
# set(CONF_INTEL_API_KEY "API Key Here")

set(SGX_MODE "Debug")

# Update all sub libraries
execute_process(
    COMMAND git submodule update --init --recursive --recommend-shallow
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    ECHO_OUTPUT_VARIABLE
    ECHO_ERROR_VARIABLE
    COMMAND_ERROR_IS_FATAL ANY
)

# Set VCPKG and Dependencies
set(VCPKG_TARGET_TRIPLET x64-linux)
set(VCPKG_OVERLAY_PORTS "")
include("${CMAKE_SOURCE_DIR}/external/vcpkg/scripts/buildsystems/vcpkg.cmake")

# Project names
project(TC4SE
    VERSION 1.0
    LANGUAGES C CXX ASM)

set(Boost_USE_STATIC_LIBS        ON)  # only find static libs
set(Boost_USE_DEBUG_LIBS        OFF)  # ignore debug libs and
set(Boost_USE_RELEASE_LIBS       ON)  # only find release libs
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME     ON)  # link Boost Static libraries
find_package(Boost REQUIRED GLOBAL)
if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
endif ()


find_package(fmt REQUIRED GLOBAL)
find_package(RapidJSON REQUIRED GLOBAL)
find_package(GTest CONFIG REQUIRED GLOBAL)
add_compile_definitions(RAPIDJSON_HAS_STDSTRING)

find_package(llhttp CONFIG REQUIRED)

# The OpenSSL should be from the system instead
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

# Requirements
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE")
add_compile_definitions(INTEL_API_KEY="${CONF_INTEL_API_KEY}")

# Add subdirectories for components
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
find_package(SGX REQUIRED)
include_directories(${SGX_INCLUDE_DIR} "include" ${CMAKE_SOURCE_DIR}/build/enclave/gen)

# Preprocessor directive to enable measurement code. Enable one by one only so it won't interfere
# with each other
# add_compile_definitions(MEASUREMENT_HANDSHAKE)
# add_compile_definitions(MEASUREMENT_PREPARATION)
add_compile_definitions(MEASUREMENT_HANDSHAKE_PACKET)

# Subdirectory containing .cpp files
add_subdirectory(common)
add_subdirectory(trusted-channel-scheme)
add_subdirectory(test)
