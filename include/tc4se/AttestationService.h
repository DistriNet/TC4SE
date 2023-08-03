#pragma once

#ifndef ENCLAVE_ABSTRACTATTESTATIONSERVICE_H
#define ENCLAVE_ABSTRACTATTESTATIONSERVICE_H

#include <cstdint>
#include <span>
#include <optional>
#include <tc4se/ErrorCode.h>

#ifndef _LIBCPP_SGX_CONFIG
#include <sgx_dcap_quoteverify.h>
#endif

namespace tc4se
{
    /**
     * @brief This structure stores TCB information per firmware model SKU. Multiple processor can have the same
     * information so it is grouped by their FMSPC value. We don't need to store beyond what we need to store. This
     * TcbInfo should be stored in the database for easy querying.
     */
    class TCBInfo
    {
      private:
        std::string fmspc;
        std::string caType; // processor or platform
        std::string tcbInfo;
        std::string tcbInfoIssuerChain;
        TCBInfo() {}
        friend class QuoteCollateral;

      public:
        TCBInfo(std::string_view fmspc, std::string_view caType, std::string&& tcbInfo,
                std::string&& tcbInfoIssuerChain):
            fmspc(fmspc),
            caType(caType), tcbInfo(std::move(tcbInfo)), tcbInfoIssuerChain(std::move(tcbInfoIssuerChain))
        {
        }

        auto& getFMSPC() const
        {
            return fmspc;
        }

        auto& getCAType() const
        {
            return caType;
        }

        auto& getTCBInfo()
        {
            return tcbInfo;
        }

        auto& getTCBInfoIssuerChain()
        {
            return tcbInfoIssuerChain;
        }
    };

    /**
     * @brief This structure stores the global certificate chain for DCAP verification. This value does not depend on
     * any device specific information since it is only a CRL (Certificate Revocation List) that is used by Quote
     * Verification to perform verification against the quote. This should be stored as a single-value config instead.
     */
    class QuoteCollateralCertificates
    {
      private:
        std::string rootCaCrl;
        std::string pckCrlIssuerChain;
        std::string pckCrl;
        std::string qeIdentityIssuerChain;
        std::string qeIdentity;

        QuoteCollateralCertificates() {}
        friend class QuoteCollateral;

      public:
        QuoteCollateralCertificates(std::string&& rootCaCrl, std::string&& pckCrlIssuerChain, std::string&& pckCrl,
                                    std::string&& qeIdentityIssuerChain, std::string&& qeIdentity):

            rootCaCrl(std::move(rootCaCrl)),
            pckCrlIssuerChain(std::move(pckCrlIssuerChain)), pckCrl(std::move(pckCrl)),
            qeIdentityIssuerChain(std::move(qeIdentityIssuerChain)), qeIdentity(std::move(qeIdentity))
        {
        }

        auto& getRootCACRL()
        {
            return rootCaCrl;
        }

        auto& getPCKCRLIssuerChain()
        {
            return pckCrlIssuerChain;
        }

        auto& getPCKCRL()
        {
            return pckCrl;
        }

        auto& getQEIdentityIssuerChain()
        {
            return qeIdentityIssuerChain;
        }

        auto& getQEIdentity()
        {
            return qeIdentity;
        }
    };

    /**
     * @brief QuoteCollateral combines the certificate and TCB information for a specific firmware, which then used by
     * the Quote Verification Enclave (QVE) to perform verification. In principle, the verification only relies on the
     * certificate and CRL validation. Therefore, in the long run, we can detach the reliance to the QVE as we can do
     * that also internally in our enclave.
     *
     */
    class QuoteCollateral
    {
      private:
        TCBInfo tcbInfo;
        QuoteCollateralCertificates collateralCerts;

      public:
        QuoteCollateral() {}
        QuoteCollateral(TCBInfo&& tcbInfo, QuoteCollateralCertificates&& certs):
            tcbInfo(std::move(tcbInfo)), collateralCerts(std::move(certs))
        {
        }

        auto& getTCBInfo()
        {
            return tcbInfo;
        }

        auto& getCollateralCerts()
        {
            return collateralCerts;
        }
    };

    class PlatformInfo
    {
        PlatformInfo() {}

        std::string encPpid;
        std::string pceId;
        std::string cpuSvn;
        std::string pceSvn;
        std::string qeId;
        std::string platformManifest;

      public:
        PlatformInfo(std::string_view encPpid, std::string_view pceId, std::string_view cpuSvn, std::string_view pceSvn,
                     std::string_view qeId, std::string_view platformManifest):
            encPpid(encPpid),
            pceId(pceId), cpuSvn(cpuSvn), pceSvn(pceSvn), qeId(qeId), platformManifest(platformManifest)
        {
        }

        auto const& getEncPpid() const
        {
            return this->encPpid;
        }

        auto const& getPceId() const
        {
            return this->pceId;
        }

        auto const& getCpuSvn() const
        {
            return this->cpuSvn;
        }

        auto const& getPceSvn() const
        {
            return this->pceSvn;
        }

        auto const& getQeId() const
        {
            return this->qeId;
        }

        auto const& getPlatformManifest() const
        {
            return this->platformManifest;
        }

        bool operator==(PlatformInfo const& other) const
        {
            return this->encPpid == other.encPpid and this->pceId == other.pceId and this->cpuSvn == other.cpuSvn and
                this->pceSvn == other.pceSvn and this->qeId == other.qeId and
                this->platformManifest == other.platformManifest;
        }
    };

#ifndef _LIBCPP_SGX_CONFIG
    struct AttestationVerificationEntities
    {
        std::time_t currentTime;
        uint32_t collateralExpirationStatus;
        sgx_ql_qv_result_t quoteVerificationResult;
        std::vector<uint8_t> supplementalData;
    };
#endif

    class AttestationService
    {
      private:
        AttestationService();

      public:
#ifndef _LIBCPP_SGX_CONFIG
        static Expect<void> setMachinePCK(std::string_view pck);
        static void setTCBInfoQueryFunction(std::function<Expect<TCBInfo>(std::string const& fmspc)>&& func);
        static void setCollateralCertQueryFunc(std::function<Expect<QuoteCollateralCertificates>()>&& func);
        static Expect<PlatformInfo> getPCKId();
        static sgx_ql_qve_collateral_t wrapCollateralToIntelStruct(QuoteCollateral& collateral);
        static Expect<std::pair<std::string, QuoteCollateral>> getAttestationMaterials(PlatformInfo const& info,
                                                                                       std::string_view const apiKey);
        static Expect<AttestationVerificationEntities>
            verifyAttestationQuote(std::span<uint8_t const> quote, sgx_ql_qe_report_info_t* qveReportInfo,
                                   std::optional<std::reference_wrapper<QuoteCollateral>> collateralRef);
#else
        static Expect<std::vector<uint8_t>> createAttestationQuote(std::span<uint8_t const> reportData);
        static Expect<std::vector<uint8_t>>
            verifyAttestationQuote(std::span<uint8_t const> quote,
                                   std::optional<std::reference_wrapper<QuoteCollateral const>> collateral = {});
        static Expect<void> verifyEnclaveSigner(std::span<uint8_t const> attestationQuote);
#endif
    };

    uint64_t getCurrentTime();

} // namespace tc4se

#endif