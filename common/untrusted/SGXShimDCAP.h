#include <sgx_ql_lib_common.h>

typedef quote3_error_t sgx_ql_get_quote_config_cb(const sgx_ql_pck_cert_id_t* p_pck_cert_id,
                                                  sgx_ql_config_t** pp_quote_config);
typedef quote3_error_t sgx_ql_free_quote_config_cb(sgx_ql_config_t* p_quote_config);

typedef quote3_error_t sgx_ql_get_quote_verification_collateral_cb(const uint8_t* fmspc, uint16_t fmspc_size,
                                                                   const char* pck_ca,
                                                                   sgx_ql_qve_collateral_t** pp_quote_collateral);

typedef quote3_error_t sgx_ql_free_quote_verification_collateral_cb(sgx_ql_qve_collateral_t* p_quote_collateral);
typedef quote3_error_t sgx_ql_get_qve_identity_cb(char** pp_qve_identity, uint32_t* p_qve_identity_size,
                                                  char** pp_qve_identity_issuer_chain,
                                                  uint32_t* p_qve_identity_issuer_chain_size);
typedef quote3_error_t sgx_ql_free_qve_identity_cb(char* p_qve_identity, char* p_qve_identity_issuer_chain);
typedef quote3_error_t sgx_ql_get_root_ca_crl_cb(uint8_t** pp_root_ca_crl, uint16_t* p_root_ca_crl_size);
typedef quote3_error_t sgx_ql_free_root_ca_crl_cb(uint8_t* p_root_ca_crl);
struct TC_ShimFunctionTable
{
    sgx_ql_get_quote_config_cb* getQuoteConfig {nullptr};
    sgx_ql_free_quote_config_cb* freeQuoteConfig {nullptr};
    sgx_ql_get_quote_verification_collateral_cb* getQuoteVerificationCollateral {nullptr};
    sgx_ql_free_quote_verification_collateral_cb* freeQuoteVerificationCollateral {nullptr};
};

extern "C" quote3_error_t sgkms_set_callback(TC_ShimFunctionTable const* funcTable);
