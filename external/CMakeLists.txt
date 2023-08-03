#Current Dependencies
# 1. Boost
# 2. RapidJSON
# 3. SGXDataCenterAttestationPrimitives

# Update all sub libraries
execute_process(
    COMMAND git submodule update --init --recursive --recommend-shallow
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    ECHO_OUTPUT_VARIABLE
    ECHO_ERROR_VARIABLE
    COMMAND_ERROR_IS_FATAL ANY
)

# RapidJSON
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/rapidjson/include)
add_library(RapidJSON INTERFACE)
target_compile_definitions(RapidJSON INTERFACE "RAPIDJSON_HAS_STDSTRING" "RAPIDJSON_HAS_CXX11_RANGE_FOR")
target_include_directories(RapidJSON INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/rapidjson/include)

# Boost library

# Build Boost.Builder in the main CMake script since it cannot be built out-of-tree
# and it is required to have this tool to build the rest of Boost library
message("Building Boost.Builder")

# Zlib
# FetchContent_Declare(
#     zlib_source
#     URL https://zlib.net/zlib-1.2.13.tar.gz
#     URL_HASH SHA256=b3a24de97a8fdbc835b9833169501030b8977031bcb54b3b3ac13740f846ab30
# )
# FetchContent_MakeAvailable(zlib_source)

set(BOOST_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/boost)
set(BOOST_BUILDER_DIR ${BOOST_BUILD_DIR}/build)
make_directory(${BOOST_BUILD_DIR})
make_directory("${BOOST_BUILD_DIR}/include")

add_custom_command(
    OUTPUT ${BOOST_BUILDER_DIR}/bootstrap.sh
    COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/boost/tools/build ${BOOST_BUILD_DIR} -r
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    USES_TERMINAL
    COMMENT "Copying b2 to build folder"
)

add_custom_command(
    OUTPUT ${BOOST_BUILDER_DIR}/b2
    COMMAND ${BOOST_BUILDER_DIR}/bootstrap.sh
    WORKING_DIRECTORY ${BOOST_BUILDER_DIR}
    USES_TERMINAL
    DEPENDS ${BOOST_BUILDER_DIR}/bootstrap.sh
    COMMENT "Building b2"
)

message("ZLib: ${CMAKE_BINARY_DIR}/lib")

add_custom_command(
    OUTPUT ${BOOST_BUILD_DIR}/include/boost
           ${BOOST_BUILD_DIR}/lib/libboost_program_options.a
           ${BOOST_BUILD_DIR}/lib/libboost_iostreams.a
    COMMAND ${BOOST_BUILDER_DIR}/b2
        --build-dir="${BOOST_BUILD_DIR}/build"
        --prefix="${BOOST_BUILD_DIR}"
        --eprefix="${BOOST_BUILD_DIR}"
        --with-serialization
        --with-program_options
        --with-iostreams
        toolset=clang
        runtime-link=shared
        link=static
        variant=release
        install

    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/boost
    USES_TERMINAL
    DEPENDS ${BOOST_BUILDER_DIR}/b2
    COMMENT "Building Boost library via b2"
)

add_custom_target(Boost_build
    DEPENDS ${BOOST_BUILD_DIR}/include/boost
    COMMENT "Building Boost library"
)


# Create an library target out of the library compilation result
add_library(Boost-ProgramOptions STATIC IMPORTED GLOBAL)
add_dependencies(Boost-ProgramOptions Boost_build)

# Specify where the library is and where to find the headers
set_target_properties(Boost-ProgramOptions
    PROPERTIES
    IMPORTED_LOCATION "${BOOST_BUILD_DIR}/lib/libboost_program_options.a"
    INTERFACE_INCLUDE_DIRECTORIES "${BOOST_BUILD_DIR}/include")
target_compile_options(Boost-ProgramOptions
    INTERFACE "-Wno-deprecated-declarations"
)

add_library(Boost-Serialization STATIC IMPORTED GLOBAL)
add_dependencies(Boost-Serialization Boost_build)
set_target_properties(Boost-Serialization
    PROPERTIES
    IMPORTED_LOCATION "${BOOST_BUILD_DIR}/lib/libboost_serialization.a"
    INTERFACE_INCLUDE_DIRECTORIES "${BOOST_BUILD_DIR}/include")

add_library(Boost-WSerialization STATIC IMPORTED GLOBAL)
add_dependencies(Boost-WSerialization Boost_build)
set_target_properties(Boost-WSerialization
    PROPERTIES
    IMPORTED_LOCATION "${BOOST_BUILD_DIR}/lib/libboost_wserialization.a"
    INTERFACE_INCLUDE_DIRECTORIES "${BOOST_BUILD_DIR}/include")

# For header only inclusion
add_library(Boost-HeaderOnly INTERFACE)
add_dependencies(Boost-HeaderOnly Boost_build)
target_include_directories(Boost-HeaderOnly INTERFACE ${BOOST_BUILD_DIR}/include)

set(Boost_INCLUDE_DIR ${BOOST_BUILD_DIR}/include)

add_subdirectory(fmt)
