#include <cstdint>
#include <vector>

#include <sgx_ql_lib_common.h>
#include <sgx_ql_quote.h>
#include <sgx_qve_header.h>
#include <sgx_quote.h>
#include <sgx_quote_3.h>
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
#include <sgx_report.h>
#include <sgx_utils.h>

#include <tc4se/Constants.h>
#include <tc4se/ErrorCode.h>
#include <tc4se/OpenSSL.h>

#include <tc4se/AttestationService.h>

using namespace tc4se;

namespace
{
    constexpr uint32_t QVE_MISC_SELECT {0x00000000};
    constexpr uint32_t QVE_MISC_SELECT_MASK {0xFFFFFFFF};

    constexpr sgx_attributes_t QVE_ATTRIBUTE {.flags = 0x1, .xfrm = 0};
    constexpr sgx_attributes_t QVE_ATTRIBUTE_MASK {.flags = 0xFFFFFFFB, .xfrm = 0};

    constexpr uint8_t QVE_MRSIGNER[] {0x8C, 0x4F, 0x57, 0x75, 0xD7, 0x96, 0x50, 0x3E, 0x96, 0x13, 0x7F,
                                      0x77, 0xC6, 0x8A, 0x82, 0x9A, 0x00, 0x56, 0xAC, 0x8D, 0xED, 0x70,
                                      0x14, 0x0B, 0x08, 0x1B, 0x09, 0x44, 0x90, 0xC5, 0x7B, 0xFF};

    constexpr uint32_t ISVSVN_THRESHOLD {3};
    constexpr sgx_prod_id_t QVE_PRODID {2};
    constexpr sgx_isv_svn_t LEAST_QVE_ISVSVN {3};
} // namespace

namespace
{
    /**
     * @brief do local attestation between our enclave and the QvE from Intel
     *
     * @param quote [IN] quote of our enclave
     * @param qveReportInfo [IN] QvE report info that is signed by our enclave's key
     * @param expirationCheckDate [IN] the date of QvE report expiration
     * @param collateralExpirationStatus [IN] the quote verification collateral expiration status
     * @param quoteVerificationResult [IN] the quote verification result
     * @param supplementalData [IN] pointer to the supplemental data
     * @param qveISVSVNThreshold [IN] the threshold of QvE ISVSVN, the ISVSVN of QvE used to verify the Quote must be
     * greater or equal to this threshold
     * @return Expect<void>
     */
    Expect<void> verifyQVEReportAndIdentity(std::span<uint8_t const> quote,
                                            sgx_ql_qe_report_info_t const& qveReportInfo,
                                            std::time_t expirationCheckDate, uint32_t collateralExpirationStatus,
                                            sgx_ql_qv_result_t quoteVerificationResult,
                                            std::span<uint8_t const> supplementalData, sgx_isv_svn_t qveISVSVNThreshold)
    {
        auto& qveReport = qveReportInfo.qe_report;

        // check if there are empty parameters
        if (quote.empty() or supplementalData.empty())
            return ErrorCode::INVALID_PARAMETER;

        // verify QvE report
        auto sgxRet {sgx_verify_report(&qveReport)};
        if (sgxRet != SGX_SUCCESS)
            return ErrorCode::QVE_VERIFICATION_FAILED;

        // verify QvE report data
        {
            sgx_sha_state_handle_t shaHandle {nullptr};
            sgxRet = sgx_sha256_init(&shaHandle);

            // Ensure the handle is closed when returning from this control structure
            std::unique_ptr<void,
                            decltype(
                                [](void* ptr)
                                {
                                    sgx_sha256_close(ptr);
                                })>
                shaHandlePtr {reinterpret_cast<void*>(shaHandle)};

            if (sgxRet != SGX_SUCCESS)
                return ErrorCode::QVE_VERIFICATION_FAILED;

            // verify nonce
            sgxRet = sgx_sha256_update(reinterpret_cast<uint8_t const*>(&qveReportInfo.nonce),
                                       sizeof(qveReportInfo.nonce), shaHandle);
            if (sgxRet != SGX_SUCCESS)
                return ErrorCode::QVE_VERIFICATION_FAILED;

            // verify quote
            sgxRet = sgx_sha256_update(quote.data(), quote.size(), shaHandle);
            if (sgxRet != SGX_SUCCESS)
                return ErrorCode::QVE_VERIFICATION_FAILED;

            // verify expiration check date
            sgxRet = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&expirationCheckDate),
                                       sizeof(expirationCheckDate), shaHandle);
            if (sgxRet != SGX_SUCCESS)
                return ErrorCode::QVE_VERIFICATION_FAILED;

            // verify collateral expiration status
            sgxRet = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&collateralExpirationStatus),
                                       sizeof(collateralExpirationStatus), shaHandle);
            if (sgxRet != SGX_SUCCESS)
                return ErrorCode::QVE_VERIFICATION_FAILED;

            // verify quote verification result
            sgxRet = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&quoteVerificationResult),
                                       sizeof(quoteVerificationResult), shaHandle);
            if (sgxRet != SGX_SUCCESS)
                return ErrorCode::QVE_VERIFICATION_FAILED;

            // verify supplemental data
            sgxRet = sgx_sha256_update(supplementalData.data(), supplementalData.size(), shaHandle);
            if (sgxRet != SGX_SUCCESS)
                return ErrorCode::QVE_VERIFICATION_FAILED;

            // verify the hashed report data
            sgx_report_data_t reportData {0};
            sgxRet = sgx_sha256_get_hash(shaHandle, reinterpret_cast<sgx_sha256_hash_t*>(&reportData));

            if (sgxRet != SGX_SUCCESS)
                return ErrorCode::QVE_VERIFICATION_FAILED;
            if (std::memcmp(&qveReportInfo.qe_report.body.report_data, &reportData, sizeof(reportData)) != 0)
                return ErrorCode::QVE_VERIFICATION_FAILED;
        }

        // verify MiscSelect from QvE report
        if ((qveReport.body.misc_select & QVE_MISC_SELECT_MASK) != QVE_MISC_SELECT)
            return ErrorCode::QVE_IDENTITY_MISMATCH;

        if ((qveReport.body.attributes.flags & QVE_ATTRIBUTE_MASK.flags) != QVE_ATTRIBUTE.flags)
            return ErrorCode::QVE_IDENTITY_MISMATCH;

        std::span<uint8_t const> mrsignerQve {QVE_MRSIGNER, sizeof(QVE_MRSIGNER)};
        std::span<uint8_t const> mrsignerReport {qveReport.body.mr_signer.m, sizeof(qveReport.body.mr_signer.m)};
        if (!std::equal(mrsignerReport.begin(), mrsignerReport.end(), mrsignerQve.begin(), mrsignerQve.end()))
            return ErrorCode::QVE_IDENTITY_MISMATCH;

        // verify Prod ID in QvE report
        if (qveReport.body.isv_prod_id != QVE_PRODID)
            return ErrorCode::QVE_IDENTITY_MISMATCH;

        // verify QvE ISV SVN in QvE report meets the minimum requires SVN when the TVL was built.
        if (qveReport.body.isv_svn < LEAST_QVE_ISVSVN)
            return ErrorCode::QVE_OUT_OF_DATE;

        // check if there has been a TCB Recovery on the QVE used to verify the report.
        // Warning: The function may return erroneous result if QvE ISV SVN has been modified maliciously.
        if (qveReport.body.isv_svn < qveISVSVNThreshold)
            return ErrorCode::QVE_OUT_OF_DATE;

        // check verification collateral expiration status
        // this value should be considered in our own attestation/verification policy
        switch (quoteVerificationResult)
        {
        case SGX_QL_QV_RESULT_OK:
            if (collateralExpirationStatus != 0)
                return ErrorCode::COLLATERAL_OUT_OF_DATE;
            // The error status below perhaps must be also returned to the user as this might indicate an outdated
            // system
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            return success;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
            return ErrorCode::COLLATERAL_INVALID_SIGNATURE;
        case SGX_QL_QV_RESULT_REVOKED:
            return ErrorCode::COLLATERAL_REVOKED;
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            return ErrorCode::VERIFICATION_RESULT_UNSPECIFIED;
        }
        return success;
    }
} // namespace

namespace tc4se
{
    /**
     * @brief Create a report that can be used to attest this enclave. This can be used for both local and remote
     * attestation.
     *
     * @param targetInfo For local attestation, the target info is the target enclave where this report will be used.
     * For remote attestation, the the target info is obtained from the Quoting Enclave.
     * @param reportData Additional data to be attached in the report.
     * @return Expect<sgx_report_t> The report which can be verified through `sgx_verify_report`
     */
    Expect<sgx_report_t> createEnclaveReport(sgx_target_info_t const& targetInfo, std::span<uint8_t const> reportData)
    {
        sgx_report_t attestationReport;
        sgx_report_data_t sgxReportData;
        sgx_report_data_t const* sgxReportDataPtr = &sgxReportData;

        if (reportData.size() == sizeof(sgx_report_data_t))
            // Prevent copying
            sgxReportDataPtr = reinterpret_cast<sgx_report_data_t const*>(reportData.data());
        else if (reportData.size() < sizeof(sgx_report_data_t))
        {
            std::memset(&sgxReportData, 0, sizeof(sgx_report_data_t));
            // memcpy is bounded through the condition that the size of sgxReportData is always bigger than
            // reportData.size
            std::memcpy(&sgxReportData, reportData.data(), reportData.size());
        }
        else
            return ErrorCode::SGX_CREATE_REPORT_FAILED; // reportDataSize bigger

        if (sgx_create_report(&targetInfo, sgxReportDataPtr, &attestationReport) != SGX_SUCCESS)
            return ErrorCode::SGX_CREATE_REPORT_FAILED;
        return attestationReport;
    }

    /**
     * @brief Create a quote for remote attestation process. This function requires the availability of Intel DCAP
     * infrastructure.
     *
     * @param reportData Additional data to be attached in the report.
     * @return Expect<std::vector<uint8_t>> Resulting quote that can be passed to the attesting/verifying party.
     */
    Expect<std::vector<uint8_t>> AttestationService::createAttestationQuote(std::span<uint8_t const> reportData)
    {
        // Get qeTargetInfo first
        sgx_target_info_t qeTargetInfo;
        uint64_t retValue {0};
        uint32_t sgxStatus;
        sgxStatus = tc4se_AttestationService_getQeTargetInfo(&retValue, &qeTargetInfo);
        if (sgxStatus != SGX_SUCCESS)
            return ErrorCode::OCALL_FAILED;
        if (retValue != 0)
            return ErrorCode::OCALL_FAILED;
        BOOST_OUTCOME_TRY(sgx_report_t report, createEnclaveReport(qeTargetInfo, reportData));

        // Get Quote Size
        uint32_t quoteSize;
        sgxStatus = tc4se_AttestationService_getAttestationQuoteSize(&retValue, &quoteSize);
        if (sgxStatus != SGX_SUCCESS)
            return ErrorCode::OCALL_FAILED;
        if (retValue != 0)
            return ErrorCode::OCALL_FAILED;

        // Get Quote
        std::vector<uint8_t> quote(quoteSize);
        sgxStatus = tc4se_AttestationService_getAttestationQuote(&retValue, &report, quote.data(), quote.size());
        if (sgxStatus != SGX_SUCCESS)
            return ErrorCode::OCALL_FAILED;
        if (retValue != 0)
            return ErrorCode::OCALL_FAILED;
        return quote;
    }

    Expect<std::vector<uint8_t>> AttestationService::verifyAttestationQuote(
        std::span<uint8_t const> quote, std::optional<std::reference_wrapper<QuoteCollateral const>> collateral)
    {
        std::time_t currentTime {};
        uint32_t collateralExpirationStatus {};
        sgx_ql_qv_result_t quoteVerificationResult {};

        // Populate report info here
        sgx_ql_qe_report_info_t qveReportInfo;
        if (sgx_self_target(&qveReportInfo.app_enclave_target_info) != SGX_SUCCESS)
            return ErrorCode::SGX_GET_TARGET_INFO_FAILED;
        sgx_read_rand(reinterpret_cast<uint8_t*>(&qveReportInfo.nonce), sizeof(qveReportInfo.nonce));

        std::vector<uint32_t> serializedCollateral;

        uint64_t retValue {0};
        uint32_t sgxStatus;
        uint32_t supplementalDataSize {};

        // Get supplemental data size
        sgxStatus = tc4se_AttestationService_getSuplementalDataSize(&retValue, &supplementalDataSize);
        if (sgxStatus != SGX_SUCCESS)
            return ErrorCode::OCALL_FAILED;
        if (retValue != 0)
            return ErrorCode::OCALL_FAILED;

        // Get verification entities
        std::vector<uint8_t> supplementalData(supplementalDataSize);
        sgxStatus = tc4se_AttestationService_verifyQuote(
            &retValue, quote.data(), quote.size(), serializedCollateral.data(), serializedCollateral.size(),
            &qveReportInfo, &currentTime, &collateralExpirationStatus, &quoteVerificationResult,
            supplementalData.data(), supplementalData.size());
        if (sgxStatus != SGX_SUCCESS)
            return ErrorCode::OCALL_FAILED;
        if (retValue != 0)
            return ErrorCode::OCALL_FAILED;

        // start verification process
        BOOST_OUTCOME_TRY(verifyQVEReportAndIdentity(quote, qveReportInfo, currentTime, collateralExpirationStatus,
                                                     quoteVerificationResult, supplementalData, ISVSVN_THRESHOLD));

        auto quotePtr = reinterpret_cast<sgx_quote3_t const*>(quote.data());

        std::vector<uint8_t> reportData;
        reportData.reserve(sizeof(quotePtr->report_body.report_data.d));
        std::copy_n(quotePtr->report_body.report_data.d, sizeof(quotePtr->report_body.report_data.d),
                    std::back_inserter(reportData));

        return reportData;
    }

    Expect<void> AttestationService::verifyEnclaveSigner(std::span<uint8_t const> attestationQuote)
    {
        auto attestationQuotePtr {reinterpret_cast<sgx_quote3_t const*>(attestationQuote.data())};

        auto challengerEnclaveReport = sgx_self_report();
        std::span<uint8_t const> challengerSigner {std::begin(challengerEnclaveReport->body.mr_signer.m),
                                                   std::end(challengerEnclaveReport->body.mr_signer.m)};
        if (challengerSigner.empty())
            return ErrorCode::ATTESTATION_VERIFICATION_FAILED;

        // extract attester's MRSIGNER from quote
        std::span<uint8_t const> attesterSigner {std::begin(attestationQuotePtr->report_body.mr_signer.m),
                                                 std::end(attestationQuotePtr->report_body.mr_signer.m)};

        if (attesterSigner.empty())
            return ErrorCode::ATTESTATION_VERIFICATION_FAILED;
        if (!std::equal(challengerSigner.begin(), challengerSigner.end(), attesterSigner.begin(), attesterSigner.end()))
            return ErrorCode::ATTESTATION_VERIFICATION_FAILED;
        return success;
    }

    Expect<void> doSelfAttestation(std::optional<std::reference_wrapper<QuoteCollateral const>> collateral)
    {
        // Generate random bytes as report data
        std::array<uint8_t, SGX_REPORT_DATA_SIZE> randomBytes;
        sgx_read_rand(randomBytes.data(), randomBytes.size());

        // Create attestation quote
        BOOST_OUTCOME_TRY(decltype(auto) attestationQuote, AttestationService::createAttestationQuote(randomBytes));

        // Verify the created quote
        BOOST_OUTCOME_TRY(decltype(auto) reportData,
                          AttestationService::verifyAttestationQuote(attestationQuote, collateral));
        BOOST_OUTCOME_TRY(AttestationService::verifyEnclaveSigner(attestationQuote));

        // Check whether the returned report data is still match with the original
        if (!std::equal(randomBytes.begin(), randomBytes.end(), reportData.begin(), reportData.end()))
            return ErrorCode::REPORT_DATA_MISMATCH;

        return success;
    }

    uint64_t getCurrentTime()
    {
        uint64_t ret;
        tc4se_getCurrentTime(&ret);
        return ret;
    }
} // namespace tc4se

extern "C"
{
    size_t __wrap_sgxssl_write(int fd, const void* buf, size_t n)
    {
        size_t retval    = 0;
        sgx_status_t ret = u_sgxssl_write(&retval, fd, buf, n);
        if (ret != SGX_SUCCESS)
        {
            return 0;
        }

        return retval;
    }

    size_t __wrap_sgxssl_read(int fd, void* buf, size_t count)
    {
        size_t retval    = 0;
        sgx_status_t ret = u_sgxssl_read(&retval, fd, buf, count);
        if (ret != SGX_SUCCESS)
            return 0;

        return retval;
    }

    int __wrap_sgxssl_close(int fd)
    {
        int retval       = 0;
        sgx_status_t ret = u_sgxssl_close(&retval, fd);
        if (ret != SGX_SUCCESS)
            return 0;

        return -1;
    }

    // Compatibility for OpenSSL 3.0 and libsgx_ttls.a
#undef EVP_PKEY_base_id
    int EVP_PKEY_base_id(const EVP_PKEY *pkey)
    {
        return EVP_PKEY_get_base_id(pkey);
    }
}