add_enclave_library(TSLEnclave
    USE_SGXSSL
    SRCS
        TSLEnclave.cpp
    EDL
    TSLEnclave.edl
    EDL_SEARCH_PATHS
        ${CMAKE_SOURCE_DIR}/include
    # LDSCRIPT
    #     ${LDS}
    LINK_WITH
        TC4SE-Trusted-Libs
)
target_link_libraries(TSLEnclave PRIVATE "-Wl,--wrap=sgxssl_write -Wl,--wrap=sgxssl_read -Wl,--wrap=sgxssl_close")

enclave_sign(TSLEnclave
    OUTPUT
        "TSLEnclave.signed.so"
    KEY 
        ${CMAKE_SOURCE_DIR}/cmake/SigningKey-Development.pem
    CONFIG 
        ${CMAKE_SOURCE_DIR}/cmake/MachineEnclave.xml
)

set(PATH_ENCLAVE_TSL ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/TSLEnclave.signed.so CACHE INTERNAL "TSLEnclave-Path")