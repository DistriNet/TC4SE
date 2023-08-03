/**
 * ErrorCode.h
 *
 * Defines the error codes that may be returned from functions running outside
 * an enclave.
 *
 */
#pragma once

#ifndef CORE_ERRORCODE_H
#define CORE_ERRORCODE_H

#if __cplusplus

#include <exception>

#ifdef _LIBCPP_SGX_CONFIG

#define BOOST_NO_EXCEPTIONS
#define BOOST_NO_CXX11_HDR_EXCEPTION

namespace std
{
    inline void sprintf(...)
    {
        // Empty stub that does nothing
    }

    struct exception_ptr
    {
        exception_ptr() {}
        template<typename... T> exception_ptr(T&&...) {}
    };

    template<typename T> inline exception_ptr make_exception_ptr(T)
    {
        return {};
    };

    template<typename... T> inline void rethrow_exception(T&&...) {}
} // namespace std
#endif

#include <boost/outcome/outcome.hpp>
#include <boost/outcome/try.hpp>
#include <cstdint>
#include <stdexcept>

#include <type_traits>

namespace boost
{
    namespace outcome = BOOST_OUTCOME_V2_NAMESPACE;
}

#define ERRORCODE_T tc4se::ErrorCode

namespace tc4se
{
    enum class ErrorCode : uint64_t
    {
        SUCCESS                                      = 0,

        /* Attestation */
        ATTESTATION_VERIFICATION_FAILED              = 1'000'000'001,
        COLLATERAL_OUT_OF_DATE                       = 1'000'000'002,
        COLLATERAL_INVALID_SIGNATURE                 = 1'000'000'003,
        COLLATERAL_REVOKED                           = 1'000'000'004,
        VERIFICATION_RESULT_UNSPECIFIED              = 1'000'000'005,

        /* OPENSSL */
        OPENSSL_BIO_WRITE_FAILED                     = 3'000'000'000,
        OPENSSL_BIO_READ_FAILED                      = 3'000'000'001,
        OPENSSL_PUBLICKEY_LOAD_FAILED                = 3'000'000'002,
        OPENSSL_BIO_INITIALIZE_FAILED                = 3'000'000'003,
        OPENSSL_X509_LOAD_FAILED                     = 3'000'000'004,
        OPENSSL_PRIVATEKEY_LOAD_FAILED               = 3'000'000'005,
        INVALID_KEY_TYPE                             = 3'000'000'006,
        DECRYPTION_FAILED                            = 3'000'000'007,
        SIGNATURE_GENERATION_FAILED                  = 3'000'000'008,
        ENCRYPTION_FAILED                            = 3'000'000'009,
        PLAINTEXT_TOO_LARGE                          = 3'000'000'010,
        SIGNATURE_VERIFICATION_FAILED                = 3'000'000'011,
        RSA_KEY_GENERATION_FAILED                    = 3'000'000'012,
        EC_KEY_GENERATION_FAILED                     = 3'000'000'013,
        INVALID_CERTIFICATE_FOR_KEY                  = 3'000'000'014,
        OPENSSL_X509_STORE_FAILED                    = 3'000'000'015,
        OPENSSL_GET_EXTENSIONS_FAILED                = 3'000'000'016,
        OPENSSL_X509V3_EXT_NOT_FOUND                 = 3'000'000'017,
        X509_GENERATION_FAILED                       = 3'000'000'018,
        OPENSSL_SUBJECT_KEY_IDENTIFIER_NOT_FOUND     = 3'000'000'019,
        OPENSSL_ASN1_TIME_CONVERSION_FAILED          = 3'000'000'020,
        OPENSSL_X509_REQ_LOAD_FAILED                 = 3'000'000'021,
        OPENSSL_PKCS12_EXTRACTION_FAILED             = 3'000'000'022,
        SSL_STORE_CERTIFICATE_FAILED                 = 3'000'000'023,
        CERTIFICATE_VERIFICATION_FAILED              = 3'000'000'024,
        HASHING_FAILED                               = 3'000'000'025,
        INTERMEDIATE_CERTIFICATE_VERIFICATION_FAILED = 3'000'000'026,
        PEER_CERTIFICATE_VERIFICATION_FAILED         = 3'000'000'027,
        CERTIFICATE_EXPIRED                          = 3'000'000'028,

        /* TLS MANAGER */
        SSL_CTX_NEW_FAILED                           = 4'000'000'000,
        INVALID_SSL_CONTEXT                          = 4'000'000'001,
        TLS1_3_UNAVAILABLE                           = 4'000'000'002,
        SSL_SET_CIPHERSUITES_FAILED                  = 4'000'000'003,
        SSL_USE_CERTIFICATE_FAILED                   = 4'000'000'004,
        SSL_NEW_FAILED                               = 4'000'000'005,
        SSL_USE_PRIVATEKEY_FAILED                    = 4'000'000'006,
        SSL_PRIVATEKEY_MISMATCHED                    = 4'000'000'007,
        SSL_SET_FD_FAILED                            = 4'000'000'008,
        SSL_ACCEPT_FAILED                            = 4'000'000'009,
        HTTP_NO_DATA_READ                            = 4'000'000'010,
        HTTP_PAYLOAD_TOO_LARGE                       = 4'000'000'011,
        OPENSSL_X509_VERIFY_FAILED                   = 4'000'000'012,
        SSL_WRITE_FAILED                             = 4'000'000'013,
        ASN1_OBJECT_CREATION_FAILED                  = 4'000'000'014,
        ASN1_STRING_CREATION_FAILED                  = 4'000'000'015,
        ASN1_STRING_SET_FAILED                       = 4'000'000'016,
        X509_EXTENSION_CREATION_FAILED               = 4'000'000'017,
        ADD_CERTIFICATE_EXTENSION_FAILED             = 4'000'000'018,
        X509_CERTIFICATE_NOT_FOUND                   = 4'000'000'019,
        SSL_CONNECT_FAILED                           = 4'000'000'020,

        /* SYSTEM UTIL */
        OS_FILE_OPEN_FAILED                          = 5'000'000'000,
        MEMORY_ALLOCATION_FAILED                     = 5'000'000'001,

        /* ATTESTATION */
        COLLATERAL_FILE_INVALID                      = 6'000'000'000,
        INVALID_PARAMETER                            = 6'000'000'001,
        QVE_VERIFICATION_FAILED                      = 6'000'000'002,
        QVE_IDENTITY_MISMATCH                        = 6'000'000'003,
        QVE_OUT_OF_DATE                              = 6'000'000'004,
        SGX_CREATE_REPORT_FAILED                     = 6'000'000'005,
        SGX_GET_QUOTE_SIZE_FAILED                    = 6'000'000'006,
        SGX_GET_QUOTE_FAILED                         = 6'000'000'007,
        SGX_GET_SUPPLEMENTAL_DATA_SIZE_FAILED        = 6'000'000'008,
        REPORT_DATA_MISMATCH                         = 6'000'000'009,

        /* SGX */
        ECALL_FAILED                                 = 7'000'000'000,
        SGX_RANDOM_GENERATION_FAILED                 = 7'000'000'001,
        KEY_DERIVATION_FAILED                        = 7'000'000'002,
        OCALL_FAILED                                 = 7'000'000'003,
        SGX_GET_TARGET_INFO_FAILED                   = 7'000'000'004,

        /* SOCKET */
        SOCKET_GENERIC_ERROR                         = 8'000'000'000,
        SOCKET_CREATE_FAILED                         = 8'000'000'001,
        SOCKET_LISTEN_FAILED                         = 8'000'000'002,
        SOCKET_PORT_OCCUPIED                         = 8'000'000'003,
        SOCKET_ACCEPT_FAILED                         = 8'000'000'004,
        SOCKET_CANNOT_FIND_HOST                      = 8'000'000'005,
        SOCKET_CANNOT_CONNECT_TO_HOST                = 8'000'000'006,
        SOCKET_CLOSED_FAILED                         = 8'000'000'007,

        /* MACHINE REGISTRATION */
        MACHINE_REGISTRATION_FAILED                  = 9'000'000'000,
        UNKNOWN_COMMAND                              = 9'000'000'001,
        SGX_GET_PCK_ID_FAILED,
        SHARED_OBJECT_NOT_FOUND,
        INVALID_CONNECTION,
        CURL_INIT_FAILED,
        HTTP_PARSING_ERROR,
        HTTP_HEADER_NOT_FOUND,

        /* OTHER */
        UNREACHABLE = 99'999'999'999,
    };

#ifndef SG_TRUSTED_BUILD
    using BoostOutcomePolicy = boost::outcome::policy::throw_bad_result_access<ErrorCode, void>;
#else
    using BoostOutcomePolicy = boost::outcome::policy::terminate;
#endif

    template<typename T> using Expect = boost::outcome::basic_result<T, ErrorCode, BoostOutcomePolicy>;

    namespace meta
    {
        template<typename T> struct ExpectTrait : std::false_type
        {
        };

        template<typename TRet> struct ExpectTrait<Expect<TRet>> : std::true_type
        {
            using ReturnType = TRet;
        };
    } // namespace meta

    // Indicates no error when returning Expect<void>.
    constexpr auto success = boost::outcome::success();

    constexpr ErrorCode unwrap(Expect<void> const& v)
    {
        if (v.has_error())
            return v.assume_error();
        else
            return ErrorCode::SUCCESS;
    }
} // namespace tc4se

#else
#include <stdint.h>
#define ERRORCODE_T uint64_t
#endif

#endif