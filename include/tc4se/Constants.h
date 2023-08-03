#pragma once

#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <cstdint>
#include <cstdio>
#include <type_traits>

#include <openssl/sha.h>
#include <sgx_attributes.h>
#include <sgx_key.h>

namespace tc4se
{
    template<typename TEnum>
        requires std::is_enum<TEnum>::value
    constexpr auto to_underlying(TEnum value)
    {
        return static_cast<std::underlying_type_t<TEnum>>(value);
    }
    namespace constants
    {
        constexpr char const* EMPTY_STRING {""};
        constexpr uint32_t RSA_PKCS1_OAEP_PADDING_SUBTRACTOR {66};
        constexpr char const* AVAILABLE_CIPHERSUITES {"TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"};
        constexpr uint32_t MAX_READ_PER_CHUNK {1024};
        constexpr uint32_t MAX_DATA_READ_WRITE {1024 * MAX_READ_PER_CHUNK};
        constexpr uint32_t MAX_PATH {4096};
        constexpr uint32_t SHA256_HASH_LENGTH {32};
        constexpr uint32_t ENCRYPTED_PPID_LENGTH = 384;
        constexpr char const* ID_ENCLAVE_SO {"libsgx_id_enclave.signed.so.1"};
        constexpr char const* PCE_ENCLAVE_SO {"libsgx_pce.signed.so.1"};

        enum class RSAPaddingMode : uint8_t
        {
            NO_PADDING         = 0,
            PKCS1_OAEP_PADDING = 1,
        };

    } // namespace constants
} // namespace tc4se

#endif