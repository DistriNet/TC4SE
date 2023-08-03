add_enclave_library(TC4SE-Server-Enclave
    USE_SGXSSL
    SRCS
        TC4SEServer.cpp
    EDL
        TC4SEServer.edl
    EDL_SEARCH_PATHS
        ${CMAKE_SOURCE_DIR}/include
    LINK_WITH
        TC4SE-Trusted-Libs
)

target_link_libraries(TC4SE-Server-Enclave PRIVATE "-Wl,--wrap=sgxssl_write -Wl,--wrap=sgxssl_read -Wl,--wrap=sgxssl_close")


enclave_sign(TC4SE-Server-Enclave
    OUTPUT
        "TC4SE-Server-Enclave.signed.so"
    KEY 
        ${CMAKE_SOURCE_DIR}/cmake/SigningKey-Development.pem
    CONFIG 
        ${CMAKE_SOURCE_DIR}/cmake/MachineEnclave.xml
)

set(PATH_ENCLAVE_TC4SE_SERVER ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/TC4SE-Server-Enclave.signed.so CACHE INTERNAL "TC4SE-Server-Enclave-Path")

add_enclave_library(TC4SE-Client-Enclave
    USE_SGXSSL
    SRCS
        TC4SEClient.cpp
    EDL
        TC4SEClient.edl
    EDL_SEARCH_PATHS
        ${CMAKE_SOURCE_DIR}/include
    LINK_WITH
        TC4SE-Trusted-Libs
)

target_link_libraries(TC4SE-Client-Enclave PRIVATE "-Wl,--wrap=sgxssl_write -Wl,--wrap=sgxssl_read -Wl,--wrap=sgxssl_close")

enclave_sign(TC4SE-Client-Enclave
    OUTPUT
        "TC4SE-Client-Enclave.signed.so"
    KEY 
        ${CMAKE_SOURCE_DIR}/cmake/SigningKey-Development.pem
    CONFIG 
        ${CMAKE_SOURCE_DIR}/cmake/MachineEnclave.xml
)

set(PATH_ENCLAVE_TC4SE_CLIENT ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/TC4SE-Client-Enclave.signed.so CACHE INTERNAL "TC4SE-Client-Enclave-Path")


