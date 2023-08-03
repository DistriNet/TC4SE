#include "SGXShimDCAP.h"

#include <sgx_ql_lib_common.h>

#ifndef tdx_ql_qve_collateral_t
typedef sgx_ql_qve_collateral_t tdx_ql_qve_collateral_t;
#endif

static TC_ShimFunctionTable cb;

extern "C"
{
    quote3_error_t sgx_ql_get_quote_config(const sgx_ql_pck_cert_id_t* p_pck_cert_id, sgx_ql_config_t** pp_quote_config)
    {
        if (!cb.getQuoteConfig || !cb.freeQuoteConfig)
            return SGX_QL_ERROR_UNEXPECTED;
        return cb.getQuoteConfig(p_pck_cert_id, pp_quote_config);
    }

    quote3_error_t sgx_ql_free_quote_config(sgx_ql_config_t* p_quote_config)
    {
        if (!cb.getQuoteConfig || !cb.freeQuoteConfig)
            return SGX_QL_ERROR_UNEXPECTED;
        return cb.freeQuoteConfig(p_quote_config);
    }

    quote3_error_t sgkms_set_callback(TC_ShimFunctionTable const* funcTable)
    {
        if (!funcTable)
            return SGX_QL_ERROR_INVALID_PARAMETER;

        cb = *funcTable;
        return SGX_QL_SUCCESS;
    }

    quote3_error_t sgx_ql_get_quote_verification_collateral(const uint8_t* fmspc, uint16_t fmspc_size,
                                                            const char* pck_ca,
                                                            sgx_ql_qve_collateral_t** pp_quote_collateral)
    {
        if (!cb.getQuoteVerificationCollateral || !cb.freeQuoteVerificationCollateral)
            return SGX_QL_ERROR_UNEXPECTED;

        return cb.getQuoteVerificationCollateral(fmspc, fmspc_size, pck_ca, pp_quote_collateral);
    }

    quote3_error_t sgx_ql_free_quote_verification_collateral(sgx_ql_qve_collateral_t* p_quote_collateral)
    {
        if (!cb.getQuoteVerificationCollateral || !cb.freeQuoteVerificationCollateral)
            return SGX_QL_ERROR_UNEXPECTED;

        return cb.freeQuoteVerificationCollateral(p_quote_collateral);
    }

    // These four function below seems to never get called within the DCAP library, but it must be defined otherwise the
    // QPL will just not work
    quote3_error_t sgx_ql_get_qve_identity(char** pp_qve_identity, uint32_t* p_qve_identity_size,
                                           char** pp_qve_identity_issuer_chain,
                                           uint32_t* p_qve_identity_issuer_chain_size)
    {
        return SGX_QL_ERROR_UNEXPECTED;
    }

    quote3_error_t sgx_ql_free_qve_identity(char* p_qve_identity, char* p_qve_identity_issuer_chain)
    {
        return SGX_QL_ERROR_UNEXPECTED;
    }

    quote3_error_t sgx_ql_get_root_ca_crl(uint8_t** pp_root_ca_crl, uint16_t* p_root_ca_crl_size)
    {
        return SGX_QL_ERROR_UNEXPECTED;
    }

    quote3_error_t sgx_ql_free_root_ca_crl(uint8_t* p_root_ca_crl)
    {
        return SGX_QL_ERROR_UNEXPECTED;
    }

    // This TDX library may be not present in the QPL interface. However, the newer DCAP seems to print some error to
    // std::cerr if it cannot find the symbol. So it is present to surpress the error.
    quote3_error_t tdx_ql_get_quote_verification_collateral(const uint8_t* fmspc, uint16_t fmspc_size,
                                                            const char* pck_ca,
                                                            tdx_ql_qve_collateral_t** pp_quote_collateral)
    {
        return SGX_QL_ERROR_UNEXPECTED;
    }

    quote3_error_t tdx_ql_free_quote_verification_collateral(tdx_ql_qve_collateral_t* p_quote_collateral)
    {
        return SGX_QL_ERROR_UNEXPECTED;
    }
}
