enable_testing()

add_untrusted_executable(TestSuite-IntelRATLS
    USE_SGXSSL
    EDL
        ${CMAKE_SOURCE_DIR}/trusted-channel-scheme/intel-ratls/IntelRATLSEnclave.edl
    EDL_SEARCH_PATHS
        ${CMAKE_SOURCE_DIR}/include
    SRCS
        TestIntelRATLS.cpp
        ${CMAKE_SOURCE_DIR}/trusted-channel-scheme/intel-ratls/ucommon.cpp
)

target_link_libraries(TestSuite-IntelRATLS PRIVATE
    GTest::gtest_main
    crypto
    TC4SE-Untrusted-Libs
    curl
    llhttp::llhttp_static
)

target_compile_definitions(TestSuite-IntelRATLS PRIVATE ENCLAVE_PATH="${PATH_ENCLAVE_INTELRATLS}")
add_dependencies(TestSuite-IntelRATLS IntelRATLSEnclave-sign)
include(GoogleTest)
gtest_discover_tests(TestSuite-IntelRATLS)

add_untrusted_executable(TestSuite-TC4SE
    USE_SGXSSL
    EDL
        ${CMAKE_SOURCE_DIR}/trusted-channel-scheme/tc4se/TC4SEClient.edl
        ${CMAKE_SOURCE_DIR}/trusted-channel-scheme/tc4se/TC4SEServer.edl
    EDL_SEARCH_PATHS
        ${CMAKE_SOURCE_DIR}/include
    SRCS
        TestTC4SE.cpp
)

target_link_libraries(TestSuite-TC4SE PRIVATE
    GTest::gtest_main
    crypto
    TC4SE-Untrusted-Libs
    curl
    llhttp::llhttp_static
)

target_compile_definitions(TestSuite-TC4SE PRIVATE 
                                SERVER_ENCLAVE_PATH="${PATH_ENCLAVE_TC4SE_SERVER}"
                                CLIENT_ENCLAVE_PATH="${PATH_ENCLAVE_TC4SE_CLIENT}")

add_dependencies(TestSuite-TC4SE TC4SE-Server-Enclave-sign)
add_dependencies(TestSuite-TC4SE TC4SE-Client-Enclave-sign)
gtest_discover_tests(TestSuite-TC4SE)

add_untrusted_executable(TestSuite-TSL
    USE_SGXSSL
    EDL
        ${CMAKE_SOURCE_DIR}/trusted-channel-scheme/trusted-socket-layer/TSLEnclave.edl
    EDL_SEARCH_PATHS
        ${CMAKE_SOURCE_DIR}/include
    SRCS
        TestTSL.cpp
)

target_link_libraries(TestSuite-TSL PRIVATE
    GTest::gtest_main
    crypto
    TC4SE-Untrusted-Libs
    curl
    llhttp::llhttp_static
)

target_compile_definitions(TestSuite-TSL PRIVATE ENCLAVE_PATH="${PATH_ENCLAVE_TSL}")
add_dependencies(TestSuite-TSL TSLEnclave-sign)
include(GoogleTest)
gtest_discover_tests(TestSuite-TSL)
