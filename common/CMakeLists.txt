# AttestationService
set(SGX_ATTESTATION_DIR ${CMAKE_SOURCE_DIR}/external/SGXDataCenterAttestationPrimitives)
set(QUOTE_GENERATION_DIR ${SGX_ATTESTATION_DIR}/QuoteGeneration)
set(QUOTE_VERIFY_DIR ${SGX_ATTESTATION_DIR}/QuoteVerification)

# Add shim library
add_library(AttestationShim SHARED untrusted/SGXShimDCAP.cpp)
target_include_directories(AttestationShim PRIVATE ${APP_INC_DIRS})
target_compile_options(AttestationShim PRIVATE -fPIC)

file(GENERATE
        OUTPUT gen/ShimEmbedded.S
        CONTENT "
    .global ShimEmbedded_Begin
    .global ShimEmbedded_End
    .section        .note.GNU-stack,\"\",@progbits
    .rodata
ShimEmbedded_Begin:
    .align 0x1000
    .incbin \"${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libAttestationShim.so\"
ShimEmbedded_End:")

file(GENERATE
    OUTPUT gen/ShimEmbedded.h
    CONTENT "
#if __cplusplus
#include <cstdint>
#define CDECL extern \"C\"
#else
#include <stdint.h>
#define CDECL extern
#endif
CDECL uint8_t const ShimEmbedded_Begin;
CDECL uint8_t const ShimEmbedded_End;")

add_library(ShimEmbedded OBJECT ${CMAKE_CURRENT_BINARY_DIR}/gen/ShimEmbedded.S)
set_target_properties(ShimEmbedded PROPERTIES LINKER_LANGUAGE CXX)
add_dependencies(ShimEmbedded AttestationShim)
set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/gen/ShimEmbedded.S PROPERTIES
    OBJECT_DEPENDS ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libAttestationShim.so)

add_trusted_library(TC4SE-Trusted-Libs
    USE_SGXSSL
    EDL
        ${CMAKE_SOURCE_DIR}/include/tc4se/TC4SETrustedLibs.edl
    EDL_SEARCH_PATHS
        ${CMAKE_SOURCE_DIR}/include
    SRCS
        trusted/TrustedAttestationService.cpp
        openssl/AsymmetricKey.cpp
        openssl/SSLObject.cpp
        openssl/VectorBIO.cpp
        openssl/X509Certificate.cpp)

add_untrusted_library(TC4SE-Untrusted-Libs STATIC
    USE_SGXSSL
    EDL
        ${SGX_ATTESTATION_DIR}/QuoteGeneration/quote_wrapper/quote/id_enclave/id_enclave.edl
    EDL_SEARCH_PATHS
        ${CMAKE_SOURCE_DIR}/include
    SRCS
        openssl/AsymmetricKey.cpp
        openssl/SSLObject.cpp
        openssl/VectorBIO.cpp
        openssl/X509Certificate.cpp
        untrusted/AttestationService.cpp
        untrusted/CurlUtil.cpp
        untrusted/SocketManager.cpp)

target_include_directories(TC4SE-Untrusted-Libs PRIVATE 
    ${SGX_ATTESTATION_DIR}/QuoteGeneration/quote_wrapper/common/inc
    ${SGX_ATTESTATION_DIR}/QuoteGeneration/ae/inc/internal
    ${SGX_ATTESTATION_DIR}/QuoteGeneration/common/inc
    ${SGX_ATTESTATION_DIR}/QuoteGeneration/common/inc/internal
    ${SGX_ATTESTATION_DIR}/QuoteGeneration/common/inc/internal/linux)
target_link_libraries(TC4SE-Untrusted-Libs PRIVATE fmt::fmt sgx_pce_logic crypto ssl ShimEmbedded)
target_compile_options(TC4SE-Untrusted-Libs PRIVATE -include${CMAKE_CURRENT_BINARY_DIR}/gen/ShimEmbedded.h)