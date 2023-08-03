#include "SGXShimDCAP.h"

#include <bits/chrono.h>
#include <chrono>
#include <dlfcn.h>

#include <mutex>
#include <sys/mman.h>
#include <fmt/core.h>
#include <fmt/format.h>
#include <openssl/asn1.h>

#include <sgx_ql_lib_common.h>
#include <sgx_dcap_ql_wrapper.h>
#include <sgx_dcap_quoteverify.h>
#include <sgx_pce.h>
#include <sgx_quote_3.h>
#include <sgx_urts.h>
#include <user_types.h>
#include <pce_cert.h>
#include <id_enclave_u.h>

#include <tc4se/AttestationService.h>
#include <tc4se/OpenSSL.h>
#include <tc4se/SGXHandler.h>
#include <tc4se/untrusted/CurlUtil.h>

#include <optional>
#include <filesystem>
#include <fstream>

using namespace tc4se;
using namespace tc4se::openssl;

namespace
{
    class ShimDCAPLoader
    {
        friend class tc4se::AttestationService;

      private:
        int fd;
        void* dlHandle;

        typedef quote3_error_t (*sgx_ql_get_quote_config_cb)(const sgx_ql_pck_cert_id_t* p_pck_cert_id,
                                                             sgx_ql_config_t** pp_quote_config);
        typedef quote3_error_t (*sgx_ql_free_quote_config_cb)(sgx_ql_config_t* p_quote_config);
        typedef quote3_error_t (*sgkms_set_callback_cb)(sgx_ql_get_quote_config_cb quoteConfigCb,
                                                        sgx_ql_free_quote_config_cb freeQuoteConfigCb);

        static std::optional<sgx_ql_config_t> globalConfig;
        static std::function<Expect<TCBInfo>(std::string const& fmspc)> tcbQueryFunc;
        static std::function<Expect<QuoteCollateralCertificates>()> quoteCertQueryFunc;
        static std::map<sgx_ql_qve_collateral_t*, QuoteCollateral> collateralTemporaryStore;

        static quote3_error_t getQuoteConfig(const sgx_ql_pck_cert_id_t* pckCertId, sgx_ql_config_t** quoteConfigOut)
        {
            if (pckCertId == nullptr || quoteConfigOut == nullptr)
                return SGX_QL_ERROR_INVALID_PARAMETER;

            if (!globalConfig)
                return SGX_QL_ERROR_UNEXPECTED;

            // Fill the collateral, I guess
            *quoteConfigOut = &globalConfig.value();

            return SGX_QL_SUCCESS;
        }

        static quote3_error_t freeQuoteConfig(sgx_ql_config_t* quoteConfigPtr)
        {
            if (quoteConfigPtr == &globalConfig.value())
                return SGX_QL_ERROR_INVALID_PARAMETER;
            // We don't care since it is a static variable
            return SGX_QL_SUCCESS;
        }

        static quote3_error_t getQuoteVerificationCollateral(const uint8_t* fmspc, uint16_t fmspc_size,
                                                             const char* pck_ca,
                                                             sgx_ql_qve_collateral_t** pp_quote_collateral)
        {
            // Use the std::function approach where the SGXAttestationService can simply query the function to get
            // the TCBInfo object that they can use. If the function is not set, we just return UNEXPECTED because
            // we expect the caller of sgx_qv_verify_quote to supply their own collateral information.
            if (!tcbQueryFunc)
                return SGX_QL_NO_QUOTE_COLLATERAL_DATA;

            if (fmspc_size != 6) // This is invalid argument
                return SGX_QL_ERROR_UNEXPECTED;

            std::string fmspcValue {reinterpret_cast<char const*>(fmspc), fmspc_size};
            auto tcbInfoOutcome = tcbQueryFunc(fmspcValue);
            if (!tcbInfoOutcome)
                return SGX_QL_NO_QUOTE_COLLATERAL_DATA;

            // Then we also need to obtain the Quote Certificates from Config
            auto quoteCertOutcome = quoteCertQueryFunc();
            if (!quoteCertOutcome)
                return SGX_QL_NO_QUOTE_COLLATERAL_DATA;

            // Initialize the collateral object, and store the backing value in our internal store
            *pp_quote_collateral = new sgx_ql_qve_collateral_t;
            auto res             = collateralTemporaryStore.emplace(
                *pp_quote_collateral,
                QuoteCollateral {std::move(tcbInfoOutcome.assume_value()), std::move(quoteCertOutcome.assume_value())});

            **pp_quote_collateral = AttestationService::wrapCollateralToIntelStruct(res.first->second);
            return SGX_QL_SUCCESS;
        }

        static quote3_error_t freeQuoteVerificationCollateral(sgx_ql_qve_collateral_t* p_quote_collateral)
        {
            if (!p_quote_collateral)
                return SGX_QL_SUCCESS; // trying to free nullptr.

            auto val = collateralTemporaryStore.erase(p_quote_collateral);
            if (val == 0)
                return SGX_QL_ERROR_UNEXPECTED;

            delete p_quote_collateral;
            return SGX_QL_SUCCESS;
        }

      public:
        ShimDCAPLoader()
        {
            // load shim to memory-file
            fd = memfd_create("shim", MFD_CLOEXEC);
            if (fd < 0)
                throw std::runtime_error("Cannot create shim file");
            write(fd, &ShimEmbedded_Begin, (&ShimEmbedded_End - &ShimEmbedded_Begin));

            auto shimFile = fmt::format("/proc/{}/fd/{}", getpid(), fd);

            // dlopen the file
            dlHandle      = dlopen(shimFile.c_str(), RTLD_NOW);
            if (dlHandle == nullptr)
                throw std::runtime_error(fmt::format("Cannot open shim library: {} - size: {}", dlerror(),
                                                     (&ShimEmbedded_End - &ShimEmbedded_Begin)));

            // Find function to set callback
            auto func = reinterpret_cast<decltype(sgkms_set_callback)*>(dlsym(dlHandle, "sgkms_set_callback"));
            if (func == nullptr)
                throw std::runtime_error("Cannot load set callback function from shim");

            // Detour to our own implementation

            TC_ShimFunctionTable funcTable {.getQuoteConfig                  = getQuoteConfig,
                                            .freeQuoteConfig                 = freeQuoteConfig,
                                            .getQuoteVerificationCollateral  = getQuoteVerificationCollateral,
                                            .freeQuoteVerificationCollateral = freeQuoteVerificationCollateral};
            func(&funcTable);

            // Trick the SGX to load our shim library
            sgx_ql_set_path(SGX_QL_QPL_PATH, shimFile.c_str());
            sgx_qv_set_path(SGX_QV_QPL_PATH, shimFile.c_str());
            // We should force the library loading to the installed file
            sgx_qv_set_path(SGX_QV_QVE_PATH, "/lib64/libsgx_qve.signed.so.1");
            sgx_qe_set_enclave_load_policy(SGX_QL_DEFAULT);
            sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
        }
        ~ShimDCAPLoader()
        {
            close(fd);
        }

        static Expect<void> setMachinePCK(std::string_view pckCert)
        {
            constexpr char const* SGX_EXTENSION_OID        = "1.2.840.113741.1.13.1";
            constexpr char const* SGX_EXTENSION_OID_TCB    = "1.2.840.113741.1.13.1.2";
            constexpr char const* SGX_EXTENSION_OID_PCESVN = "1.2.840.113741.1.13.1.2.17";
            constexpr char const* SGX_EXTENSION_OID_CPUSVN = "1.2.840.113741.1.13.1.2.18";

            // Copy to global string
            if (pckCert.length() > INT32_MAX)
                std::abort(); // Prevent possible malicious buffer overflow

            // Get info from the certificate Library
            std::optional<sgx_isv_svn_t> pce_isvsvn;
            std::optional<sgx_cpu_svn_t> cpuSvn;

            BOOST_OUTCOME_TRY(auto cert, openssl::X509Certificate::fromPEM(pckCert));

            for (auto [asn1, octet]: cert[0].extensions())
            {
                BOOST_OUTCOME_TRY(auto asn1str, openssl::objToString(asn1));
                if (asn1str == SGX_EXTENSION_OID)
                {
                    // we need to get PCE ISVSVN and CPU SVN from the certificate

                    // The top level that is stored in the X509 extension certificate:
                    // SGX_EXTENSION_OID with the type of OCTET STRING, meaning that IT IS A BINARY.
                    if (octet->type != V_ASN1_OCTET_STRING)
                        return ErrorCode::COLLATERAL_FILE_INVALID;

                    const auto* data      = octet->data;
                    auto rawExtensionData = OpenSSLRef {d2i_ASN1_TYPE(nullptr, &data, octet->length)};
                    if (rawExtensionData->type != V_ASN1_SEQUENCE)
                        return ErrorCode::COLLATERAL_FILE_INVALID;

                    // That octet string IS ACTUALLY a binary of another ASN1_TYPE which is a ASN1_SEQUENCE which is
                    // basically a LIST of ASN1_TYPE objects.
                    data = rawExtensionData->value.sequence->data;
                    auto extensionElements =
                        OpenSSLRef {d2i_ASN1_SEQUENCE_ANY(nullptr, &data, rawExtensionData->value.sequence->length)};

                    // Then you need to iterate the list to find what you want
                    for (int i = 0, count = sk_ASN1_TYPE_num(extensionElements); i < count; i++)
                    {
                        // Get the object
                        auto oidObject           = sk_ASN1_TYPE_value(extensionElements, i);

                        // Wrap it inside a lambda
                        constexpr auto extractor = [](auto oidTupleWrapper)
                            -> Expect<std::tuple<std::string, ASN1_TYPE*, decltype(extensionElements)>>
                        {
                            if (oidTupleWrapper->type != V_ASN1_SEQUENCE)
                                return ErrorCode::COLLATERAL_FILE_INVALID;

                            const auto* data = oidTupleWrapper->value.sequence->data;
                            auto tuple       = OpenSSLRef {
                                d2i_ASN1_SEQUENCE_ANY(nullptr, &data, oidTupleWrapper->value.sequence->length)};

                            if (sk_ASN1_TYPE_num(tuple) == 0)
                                return ErrorCode::COLLATERAL_FILE_INVALID;

                            auto nameObject = sk_ASN1_TYPE_value(tuple, 0);
                            if (nameObject->type != V_ASN1_OBJECT)
                                return ErrorCode::COLLATERAL_FILE_INVALID;

                            // 😑🔫
                            auto len = OBJ_obj2txt(nullptr, 0, nameObject->value.object, 1);
                            std::string name;
                            name.resize(len);
                            // According to C++ standard, this is okay (at least since C++17)
                            OBJ_obj2txt(name.data(), name.size() + 1, nameObject->value.object, 1);

                            auto var = sk_ASN1_TYPE_value(tuple, 1);

                            // The tuple object ownership must be transferred outside as well as the var value depends
                            // on it
                            return std::tuple {std::move(name), var, std::move(tuple)};
                        };

                        auto [name, tupleValue, _] = BOOST_OUTCOME_TRYX(extractor(oidObject));

                        if (name != SGX_EXTENSION_OID_TCB)
                            continue;

                        if (tupleValue->type != V_ASN1_SEQUENCE)
                            return ErrorCode::COLLATERAL_FILE_INVALID;

                        data = tupleValue->value.sequence->data;
                        auto extensionElements =
                            OpenSSLRef {d2i_ASN1_SEQUENCE_ANY(nullptr, &data, tupleValue->value.sequence->length)};

                        for (int j = 0, countJ = sk_ASN1_TYPE_num(extensionElements); j < countJ; j++)
                        {
                            auto [name, tupleValue, _] =
                                BOOST_OUTCOME_TRYX(extractor(sk_ASN1_TYPE_value(extensionElements, j)));

                            if (name == SGX_EXTENSION_OID_PCESVN)
                            {
                                if (tupleValue->type != V_ASN1_INTEGER)
                                    return ErrorCode::COLLATERAL_FILE_INVALID;

                                pce_isvsvn = ASN1_INTEGER_get(tupleValue->value.integer);
                            }
                            else if (name == SGX_EXTENSION_OID_CPUSVN)
                            {
                                if (tupleValue->type != V_ASN1_OCTET_STRING)
                                    return ErrorCode::COLLATERAL_FILE_INVALID;

                                // The size MUST be as wide as the CPUSVN length
                                if (tupleValue->value.octet_string->length != sizeof(cpuSvn->svn))
                                    return ErrorCode::COLLATERAL_FILE_INVALID;

                                // Set value
                                cpuSvn.emplace();

                                // This memcpy is safe because we are agreeing the length of svn and the data
                                std::memcpy(&cpuSvn->svn, tupleValue->value.octet_string->data,
                                            sizeof(globalConfig->cert_cpu_svn.svn));
                            }
                            else
                                continue;
                        }
                    }
                }
            }
            if (!cpuSvn || !pce_isvsvn)
                return ErrorCode::COLLATERAL_FILE_INVALID;

            static std::string pckCertBuf {pckCert};
            globalConfig = sgx_ql_config_t {.version          = SGX_QL_CONFIG_VERSION_1,
                                            .cert_cpu_svn     = *cpuSvn,
                                            .cert_pce_isv_svn = *pce_isvsvn,
                                            .cert_data_size   = static_cast<uint32_t>(pckCertBuf.length()),
                                            .p_cert_data      = reinterpret_cast<uint8_t*>(pckCertBuf.data())};

            return success;
        }
    };

} // namespace

// This will ensure it will be loaded once and for all on every start up of our program
ShimDCAPLoader loader {};
std::optional<sgx_ql_config_t> ShimDCAPLoader::globalConfig {};

decltype(ShimDCAPLoader::tcbQueryFunc) ShimDCAPLoader::tcbQueryFunc;
decltype(ShimDCAPLoader::quoteCertQueryFunc) ShimDCAPLoader::quoteCertQueryFunc;
decltype(ShimDCAPLoader::collateralTemporaryStore) ShimDCAPLoader::collateralTemporaryStore;

Expect<void> AttestationService::setMachinePCK(std::string_view pckCert)
{
    return ShimDCAPLoader::setMachinePCK(pckCert);
}

void AttestationService::setTCBInfoQueryFunction(std::function<Expect<TCBInfo>(std::string const& fmspc)>&& func)
{
    ShimDCAPLoader::tcbQueryFunc = std::move(func);
}

void AttestationService::setCollateralCertQueryFunc(std::function<Expect<QuoteCollateralCertificates>()>&& func)
{
    ShimDCAPLoader::quoteCertQueryFunc = std::move(func);
}

sgx_ql_qve_collateral_t AttestationService::wrapCollateralToIntelStruct(QuoteCollateral& collateral)
{
    // Apparently since C++11, all std::string now must allocate the space for null character to ensure
    // the c_str is always constant time. Modern C++ now allocates [0...size()] which means that the string buffer
    // size is always size() + 1. So, write to str.data()[size()] does not become undefined behavior

    return {.major_version        = 3,
            .minor_version        = 0,
            .tee_type             = 0x00000000,

            .pck_crl_issuer_chain = collateral.getCollateralCerts().getPCKCRLIssuerChain().data(),
            .pck_crl_issuer_chain_size =
                static_cast<uint32_t>(collateral.getCollateralCerts().getPCKCRLIssuerChain().size() + 1),

            .root_ca_crl           = collateral.getCollateralCerts().getRootCACRL().data(),
            .root_ca_crl_size      = static_cast<uint32_t>(collateral.getCollateralCerts().getRootCACRL().size() + 1),

            .pck_crl               = collateral.getCollateralCerts().getPCKCRL().data(),
            .pck_crl_size          = static_cast<uint32_t>(collateral.getCollateralCerts().getPCKCRL().size() + 1),

            .tcb_info_issuer_chain = collateral.getTCBInfo().getTCBInfoIssuerChain().data(),
            .tcb_info_issuer_chain_size =
                static_cast<uint32_t>(collateral.getTCBInfo().getTCBInfoIssuerChain().size() + 1),

            .tcb_info                 = collateral.getTCBInfo().getTCBInfo().data(),
            .tcb_info_size            = static_cast<uint32_t>(collateral.getTCBInfo().getTCBInfo().size() + 1),

            .qe_identity_issuer_chain = collateral.getCollateralCerts().getQEIdentityIssuerChain().data(),
            .qe_identity_issuer_chain_size =
                static_cast<uint32_t>(collateral.getCollateralCerts().getQEIdentityIssuerChain().size() + 1),

            .qe_identity      = collateral.getCollateralCerts().getQEIdentity().data(),
            .qe_identity_size = static_cast<uint32_t>(collateral.getCollateralCerts().getQEIdentity().size() + 1)};
}

namespace
{
    Expect<std::string> getSharedObjectPath(std::string_view sharedObject)
    {
        std::filesystem::path root("/");
        std::filesystem::path lib64("lib64");
        std::filesystem::path usr("usr");

        std::filesystem::path sharedObjectPath(sharedObject);

        std::filesystem::path possiblePath(root / lib64 / sharedObject);
        std::filesystem::path possiblePath2(root / usr / lib64 / sharedObject);

        if (std::filesystem::exists(possiblePath.c_str()))
            return possiblePath.c_str();
        if (std::filesystem::exists(possiblePath2.c_str()))
            return possiblePath2.c_str();

        return ErrorCode::SHARED_OBJECT_NOT_FOUND;
    }

    struct InitializePCKLib
    {
        InitializePCKLib()
        {
            auto pceEnclavePathOutcome = getSharedObjectPath(constants::PCE_ENCLAVE_SO);
            if (!pceEnclavePathOutcome)
                std::abort();
            sgx_set_pce_path(pceEnclavePathOutcome.assume_value().c_str());
        }
    } initializePCKLib;
} // namespace

Expect<PlatformInfo> AttestationService::getPCKId()
{
    try
    {
        BOOST_OUTCOME_TRY(decltype(auto) idEnclavePath, getSharedObjectPath(constants::ID_ENCLAVE_SO));

        tc4se::sgx::EnclaveHandler ideEnclave {idEnclavePath, 0};

        sgx_key_128bit_t platformId;
        sgx_status_t ret;

        auto getIdStatus = ide_get_id(ideEnclave, &ret, &platformId);
        if (getIdStatus != SGX_SUCCESS)
            return ErrorCode::SGX_GET_PCK_ID_FAILED;

        sgx_target_info_t pceTargetInfo;
        sgx_isv_svn_t pceIsvSvn;
        auto getTargetInfoStatus = sgx_pce_get_target(&pceTargetInfo, &pceIsvSvn);

        if (getTargetInfoStatus != SGX_PCE_SUCCESS)
            return ErrorCode::SGX_GET_PCK_ID_FAILED;

        std::vector<uint8_t> encPublicKeyVec(REF_RSA_OAEP_3072_MOD_SIZE + REF_RSA_OAEP_3072_EXP_SIZE);
        sgx_report_t idEnclaveReport;

        auto getPCEEnryptKey =
            ide_get_pce_encrypt_key(ideEnclave, &ret, &pceTargetInfo, &idEnclaveReport, PCE_ALG_RSA_OAEP_3072,
                                    PPID_RSA3072_ENCRYPTED, encPublicKeyVec.size(), encPublicKeyVec.data());
        if (getPCEEnryptKey != SGX_SUCCESS or ret != SGX_SUCCESS)
            return ErrorCode::SGX_GET_PCK_ID_FAILED;

        std::vector<uint8_t> encryptedPPIDVec(REF_RSA_OAEP_3072_MOD_SIZE);
        uint32_t encryptedPPIDRetSize;
        pce_info_t pceInfo;
        uint8_t signatureScheme;

        auto getPCInfo = sgx_get_pce_info(&idEnclaveReport, encPublicKeyVec.data(), encPublicKeyVec.size(),
                                          PCE_ALG_RSA_OAEP_3072, encryptedPPIDVec.data(), encryptedPPIDVec.size(),
                                          &encryptedPPIDRetSize, &pceInfo.pce_isvn, &pceInfo.pce_id, &signatureScheme);
        if (getPCInfo != SGX_PCE_SUCCESS)
            return ErrorCode::SGX_GET_PCK_ID_FAILED;

        if (signatureScheme != PCE_NIST_P256_ECDSA_SHA256)
            return ErrorCode::SGX_GET_PCK_ID_FAILED;

        if (encryptedPPIDRetSize != constants::ENCRYPTED_PPID_LENGTH)
            return ErrorCode::SGX_GET_PCK_ID_FAILED;

        std::string enc_ppid = fmt::format("{:02x}", fmt::join(encryptedPPIDVec, ""));
        std::string cpu_svn  = fmt::format("{:02X}",
                                           fmt::join(std::span<uint8_t const> {idEnclaveReport.body.cpu_svn.svn,
                                                                               sizeof(idEnclaveReport.body.cpu_svn.svn)},
                                                     ""));
        std::string ppid =
            fmt::format("{:02X}", fmt::join(std::span<uint8_t const> {platformId, sizeof(platformId)}, ""));

        // converted to little endian
        auto pceId = fmt::format("{:04X}", ((((pceInfo.pce_id << 8) & 0xff00) | ((pceInfo.pce_id >> 8) & 0x00ff))));
        // converted to little endian
        auto pce_isvn =
            fmt::format("{:04X}", (((pceInfo.pce_isvn << 8) & 0xff00) | ((pceInfo.pce_isvn >> 8) & 0x00ff)));

        // std::string platformManifestStr {};
        // auto outcomeGetPlatformManifest = getPlatformManifest();
        // if (outcomeGetPlatformManifest)
        //     platformManifestStr = fmt::format("{:02x}", fmt::join(outcomeGetPlatformManifest.assume_value(), ""));

        return PlatformInfo(enc_ppid, pceId, cpu_svn, pce_isvn, ppid, "");
    }
    catch (std::exception const& e)
    {
        return ErrorCode::SGX_GET_PCK_ID_FAILED;
    }
}

/**
 * @brief Get the required components for attestation to works, which includes the PCK certificate, and the quote
 * collateral
 *
 * @param info Platform info that will generate the attestation
 * @param apiKey API Key to Intel service
 * @return Expect<std::pair<std::string, core::QuoteCollateral>> Pair of PCK certificate and QuoteCollateral
 */
Expect<std::pair<std::string, QuoteCollateral>>
    AttestationService::getAttestationMaterials(PlatformInfo const& info, std::string_view const apiKey)
{
    std::string_view INTEL_API_URL         = "https://api.trustedservices.intel.com/sgx/certification/v4",
                     INTEL_API_KEY_NAME    = "Ocp-Apim-Subscription-Key",
                     INTEL_SGX_ROOT_CA_URL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der";
    std::string completeUrl = fmt::format("{}/pckcert?encrypted_ppid={}&pceid={}&pcesvn={}&cpusvn={}", INTEL_API_URL,
                                          info.getEncPpid(), info.getPceId(), info.getPceSvn(), info.getCpuSvn());
    std::vector<std::string> requestHeader {fmt::format("{}: {}", INTEL_API_KEY_NAME, apiKey)};

    BOOST_OUTCOME_TRY(HTTPPayload response, sendCurlRequest(completeUrl, requestHeader));

    // Get PCK cert
    std::stringstream ss;
    ss << response.getBody();
    BOOST_OUTCOME_TRY(auto caChain, response.getHeader("SGX-PCK-Certificate-Issuer-Chain"));
    BOOST_OUTCOME_TRY(auto caChainUnescaped, urlDecode(caChain));
    ss << caChainUnescaped;

    BOOST_OUTCOME_TRY(auto fmspc, response.getHeader("SGX-FMSPC"));
    BOOST_OUTCOME_TRY(auto caType, response.getHeader("SGX-PCK-Certificate-CA-Type"));

    // Get TCB
    auto tcbUrl {fmt::format("{}/tcb?fmspc={}", INTEL_API_URL, fmspc)};
    BOOST_OUTCOME_TRY(auto tcbResponse, sendCurlRequest(tcbUrl));

    BOOST_OUTCOME_TRY(auto tcbInfoIssuerChain, tcbResponse.getHeader("TCB-Info-Issuer-Chain"));
    BOOST_OUTCOME_TRY(auto tcbInfoIssuerChainUnescaped, urlDecode(tcbInfoIssuerChain));

    // Get collateral certificates
    // Get pckcrl
    auto pckcrlUrl = fmt::format("{}/pckcrl?ca={}", INTEL_API_URL, caType);
    BOOST_OUTCOME_TRY(HTTPPayload pckcrlResponse, sendCurlRequest(pckcrlUrl));
    BOOST_OUTCOME_TRY(auto pckcrlIssuerChain, pckcrlResponse.getHeader("SGX-PCK-CRL-Issuer-Chain"));
    BOOST_OUTCOME_TRY(auto pckcrlIssuerChainUnescaped, urlDecode(pckcrlIssuerChain));

    // Get QE Identity
    auto qeidentityUrl = fmt::format("{}/qe/identity", INTEL_API_URL);
    BOOST_OUTCOME_TRY(HTTPPayload qeidentityResponse, sendCurlRequest(qeidentityUrl));
    BOOST_OUTCOME_TRY(auto qeIdentIssuerChain, qeidentityResponse.getHeader("SGX-Enclave-Identity-Issuer-Chain"));
    BOOST_OUTCOME_TRY(auto qeIdentIssuerChainnUnescaped, urlDecode(qeIdentIssuerChain));

    // Get Intel Root CRL
    BOOST_OUTCOME_TRY(HTTPPayload rootCAcrlResponse, sendCurlRequest(INTEL_SGX_ROOT_CA_URL));

    BOOST_OUTCOME_TRY(auto rootCrlPem,
                      openssl::crlDERtoPEM({reinterpret_cast<uint8_t const*>(rootCAcrlResponse.getBody().data()),
                                            rootCAcrlResponse.getBody().size()}));

    // (clang-format does some weird stuff here)
    // clang-format off
    return std::pair {
        ss.str(),
        QuoteCollateral {
            TCBInfo {
                {fmspc.data(), fmspc.size()}, {caType.data(), caType.size()},
                std::string {tcbResponse.getBody()},
                std::move(tcbInfoIssuerChainUnescaped)
            },
            QuoteCollateralCertificates {
                std::move(rootCrlPem), std::move(pckcrlIssuerChainUnescaped),
                std::string {pckcrlResponse.getBody()}, std::move(qeIdentIssuerChainnUnescaped),
                std::string {qeidentityResponse.getBody()}
            }
        }
    };
    // clang-format on
}

Expect<AttestationVerificationEntities>
    AttestationService::verifyAttestationQuote(std::span<uint8_t const> quote, sgx_ql_qe_report_info_t* qveReportInfo,
                                               std::optional<std::reference_wrapper<QuoteCollateral>> collateralRef)
{
    AttestationVerificationEntities attestationVerificationEntities;

    // This should be called only once
    // So I guess it is better to actually have a global function and set all these value in global
    uint32_t supplementalDataSize {};
    if (sgx_qv_get_quote_supplemental_data_size(&supplementalDataSize) != SGX_QL_SUCCESS)
        return ErrorCode::SGX_GET_QUOTE_SIZE_FAILED;

    attestationVerificationEntities.supplementalData.resize(supplementalDataSize);
    attestationVerificationEntities.currentTime =
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

    if (quote.size() < sizeof(sgx_quote3_t))
        return ErrorCode::ATTESTATION_VERIFICATION_FAILED; // This is invalid quote, because it is smaller than the
                                                           // expected quote structure

    // If the collateral is supplied by the caller, deserialize and pass as the collateral
    // otherwise, we will pass nullptr and let our shim library be called and query our local database.
    // This is to support mechanism where the collateral is passed along with the quote.

    // We can trust the collateral provided by the attested party since the Quoting Enclave hardcode Intel's root
    // public key, which makes the entire verification can be trusted to root at Intel. If in any case the attested
    // party tries to forge their quote by attaching a collateral that validates their quote, they still cannot do
    // that because their collateral will not root into Intel's public key, and the quote verification will be
    // failed.

    // This is made to enable a use case where the verifier cannot have direct access to the internet to contact
    // Intel server (or PCCS) to obtain the collateral, and especially to simplify passing the collateral on-demand,
    // rather than caching it internally.
    std::optional<sgx_ql_qve_collateral_t> collateral;
    if (collateralRef.has_value())
        collateral = wrapCollateralToIntelStruct(collateralRef.value());

    // untrusted quote verification
    if (qveReportInfo == nullptr)
    {
        if (auto res = sgx_qv_verify_quote(quote.data(), quote.size(), collateral ? &collateral.value() : nullptr,
                                           attestationVerificationEntities.currentTime,
                                           &attestationVerificationEntities.collateralExpirationStatus,
                                           &attestationVerificationEntities.quoteVerificationResult, nullptr,
                                           attestationVerificationEntities.supplementalData.size(),
                                           attestationVerificationEntities.supplementalData.data());
            res != SGX_QL_SUCCESS)
            return ErrorCode::ATTESTATION_VERIFICATION_FAILED;

        // check verification result
        switch (attestationVerificationEntities.quoteVerificationResult)
        {
        case SGX_QL_QV_RESULT_OK:
            if (attestationVerificationEntities.quoteVerificationResult != 0)
                return ErrorCode::COLLATERAL_OUT_OF_DATE;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            return attestationVerificationEntities;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
            return ErrorCode::COLLATERAL_INVALID_SIGNATURE;
        case SGX_QL_QV_RESULT_REVOKED:
            return ErrorCode::COLLATERAL_REVOKED;
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            return ErrorCode::VERIFICATION_RESULT_UNSPECIFIED;
        }
    }

    // trusted quote verification
    if (auto res = sgx_qv_verify_quote(quote.data(), quote.size(), collateral ? &collateral.value() : nullptr,
                                       attestationVerificationEntities.currentTime,
                                       &attestationVerificationEntities.collateralExpirationStatus,
                                       &attestationVerificationEntities.quoteVerificationResult, qveReportInfo,
                                       attestationVerificationEntities.supplementalData.size(),
                                       attestationVerificationEntities.supplementalData.data());
        res != SGX_QL_SUCCESS)
        return ErrorCode::ATTESTATION_VERIFICATION_FAILED;

    return attestationVerificationEntities;
}

namespace
{
    std::string_view fileName()
    {
        static std::string sp;
        if (sp.empty())
        {
            std::ifstream("/proc/self/comm") >> sp;
            sp.append(".txt");
        }
        return sp;
    }
} // namespace

extern "C"
{
    uint64_t tc4se_AttestationService_getQeTargetInfo(sgx_target_info_t* qeTargetInfo)
    {
        auto qe3Status = sgx_qe_get_target_info(qeTargetInfo);

        if (qe3Status != SGX_QL_SUCCESS)
        {
            std::printf("Get target info failed. Error code: 7'000'000'004\r\n");
            return 7'000'000'004;
        }

        return to_underlying(ErrorCode::SUCCESS);
    }

    uint64_t tc4se_AttestationService_getAttestationQuoteSize(uint32_t* quoteBufferSize)
    {
        uint32_t quoteSize {};
        quote3_error_t qe3Status {sgx_qe_get_quote_size(&quoteSize)};
        if (qe3Status != SGX_QL_SUCCESS)
        {
            std::printf("Get quote size failed. Error code: 6'000'000'006\r\n");
            return 6'000'000'006;
        }
        *quoteBufferSize = quoteSize;

        return to_underlying(ErrorCode::SUCCESS);
    }

    uint64_t tc4se_AttestationService_getAttestationQuote(const sgx_report_t* attestationReport, uint8_t* quoteBuffer,
                                                          uint32_t quoteBufferSize)
    {
        quote3_error_t qe3Status = sgx_qe_get_quote(attestationReport, quoteBufferSize, quoteBuffer);
        if (qe3Status != SGX_QL_SUCCESS)
        {
            std::printf("Get quote failed. Error code: 6'000'000'007\r\n");
            return 6'000'000'007;
        }

        return to_underlying(ErrorCode::SUCCESS);
    }

    uint64_t tc4se_AttestationService_getSuplementalDataSize(uint32_t* supplementalDataSize)
    {
        uint32_t supDataSize {};
        if (sgx_qv_get_quote_supplemental_data_size(&supDataSize) != SGX_QL_SUCCESS)
        {
            std::printf("Get supplemental data size failed. Error code: 6'000'000'008\r\n");
            return 6'000'000'008;
        }
        *supplementalDataSize = supDataSize;

        return to_underlying(ErrorCode::SUCCESS);
    }

    uint64_t tc4se_AttestationService_verifyQuote(uint8_t const* quoteBuf, uint32_t quoteBufSize,
                                                  uint32_t const* collateralBuf, uint32_t collateralBufSize,
                                                  sgx_ql_qe_report_info_t* qveReportInfo, time_t* currentTime,
                                                  uint32_t* collateralExpirationStatus,
                                                  sgx_ql_qv_result_t* quoteVerificationResult,
                                                  uint8_t* supplementalDataBuffer, uint32_t suplementalDataSize)
    {
        std::span quote {quoteBuf, quoteBufSize};
        std::span serializedCollateral {collateralBuf, collateralBufSize};

        auto outcomeVerEntities {AttestationService::verifyAttestationQuote(quote, qveReportInfo, std::nullopt)};
        if (!outcomeVerEntities)
        {
            std::printf(
                "Verify quote failed. Error code: %lu\r\n",
                to_underlying(outcomeVerEntities.assume_error())); // Needs to check the NO_QUOTE_COLLATERAL_DATA
                                                                   // and return to the caller
            return to_underlying(outcomeVerEntities.assume_error());
        }
        auto attestationVerificationEntities {outcomeVerEntities.assume_value()};

        *currentTime                = attestationVerificationEntities.currentTime;
        *collateralExpirationStatus = attestationVerificationEntities.collateralExpirationStatus;
        *quoteVerificationResult    = attestationVerificationEntities.quoteVerificationResult;
        std::copy_n(attestationVerificationEntities.supplementalData.data(), suplementalDataSize,
                    supplementalDataBuffer);

        return to_underlying(ErrorCode::SUCCESS);
    }

    uint64_t tc4se_getCurrentTime()
    {
        return std::chrono::duration_cast<std::chrono::microseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    std::mutex mtx;

    void tc4se_printDebug(const char* str)
    {
        std::lock_guard<std::mutex> printLock {mtx};
#if defined(MEASUREMENT_PREPARATION) || defined(MEASUREMENT_HANDSHAKE) || defined(MEASUREMENT_HANDSHAKE_PACKET)
        std::fstream out {fileName().data(), std::fstream::out | std::fstream::app};
#else
        auto& out {std::cout};
#endif
        out << str << std::endl;
    }
}