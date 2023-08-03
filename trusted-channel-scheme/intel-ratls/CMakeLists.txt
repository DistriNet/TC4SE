add_enclave_library(IntelRATLSEnclave
    USE_SGXSSL
    SRCS
        IntelRATLSEnclave.cpp
        openssl_utility.cpp
        verify_callback.cpp
        utility.cpp
        err_msg.cpp
    EDL
        IntelRATLSEnclave.edl
    EDL_SEARCH_PATHS
        ${CMAKE_SOURCE_DIR}/include
    # LDSCRIPT
    #     ${LDS}
    LINK_WITH
        TC4SE-Trusted-Libs
)
target_link_libraries(IntelRATLSEnclave PRIVATE "-Wl,--wrap=sgxssl_write -Wl,--wrap=sgxssl_read -Wl,--wrap=sgxssl_close")

enclave_sign(IntelRATLSEnclave
    OUTPUT
        "IntelRATLSEnclave.signed.so"
    KEY 
        ${CMAKE_SOURCE_DIR}/cmake/SigningKey-Development.pem
    CONFIG 
        ${CMAKE_SOURCE_DIR}/cmake/MachineEnclave.xml
)

set(PATH_ENCLAVE_INTELRATLS ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/IntelRATLSEnclave.signed.so CACHE INTERNAL "IntelRATLSEnclave-Path")