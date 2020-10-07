#include <sgx_qve_errlist.h>
#include <libc_mock/libcpp_mock.h>
#include <sstream>

//------------------------------------------------------------------------------
sgx_qve_errlist_t sgx_qve_errlist[] = {
    {SGX_QL_QV_RESULT_OK,
     "The Quote verification passed and is at the latest TCB level", NULL},
    {SGX_QL_QV_RESULT_CONFIG_NEEDED,
     "The SGX platform firmware and SW are at the latest security patching "
     "level but there are platform hardware configurations that may expose the "
     "enclave to vulnerabilities.",
     "These vulnerabilities can be mitigated with the appropriate platform "
     "configuration changes that will produce an SGX_QL_QV_RESULT_OK "
     "verification result"},
    {SGX_QL_QV_RESULT_SW_HARDENING_NEEDED,
     "The SGX platform firmware and SW are at the latest security patching "
     "level but there are certain vulnerabilities that can only be mitigated "
     "with software mitigations implemented by the enclave.",
     "The enclave identity policy needs to indicate whether the enclave has "
     "implemented these mitigations."},
    {SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED,
     "The SGX platform firmware and SW are at the latest security patching "
     "level but there are certain vulnerabilities that can only be mitigated "
     "with software mitigations implemented by the enclave. There are also "
     "platform hardware configurations that may expose the enclave to "
     "vulnerabilities.",
     "The enclave identity policy needs to indicate whether the enclave has "
     "implemented these mitigations. Configuration vulnerabilities can be "
     "mitigated with the appropriate platform configuration changes"},
    {SGX_QL_QV_RESULT_OUT_OF_DATE,
     "The SGX platform firmware and SW are not at the latest security patching "
     "level.",
     "The platform needs to be patched with firmware and/or software patches "
     "in order to produce an SGX_QL_QV_RESULT_OK verification result."},
    {SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED,
     "The SGX platform firmware and SW are not at the latest security patching "
     "level. There are also platform hardware configurations that may expose "
     "the enclave to vulnerabilities.",
     "The platform needs to be patched with firmware and/or software patches. "
     "Configuration vulnerabilities can be mitigated with the appropriate "
     "platform configuration changes."},
    {SGX_QL_QV_RESULT_INVALID_SIGNATURE,
     "The signature over the application report is invalid",
     "Terminal result."},
    {SGX_QL_QV_RESULT_REVOKED,
     "The attestation key or platform has been revoked", "Terminal result."},
    {SGX_QL_QV_RESULT_UNSPECIFIED,
     "The Quote verification failed due to an error in one of the input",
     "Terminal result."}};

//------------------------------------------------------------------------------
void qve_retrieve_error(sgx_ql_qv_result_t code, std::string &error,
                        std::string &extra) {
    size_t i, total = sizeof sgx_qve_errlist / sizeof sgx_qve_errlist[0];
    for (i = 0; i < total; ++i) {
        if (code == sgx_qve_errlist[i].err) {
            if (sgx_qve_errlist[i].msg != nullptr)
                error = sgx_qve_errlist[i].msg;
            if (sgx_qve_errlist[i].sug != nullptr)
                extra = sgx_qve_errlist[i].sug;
            break;
        }
    }
    if (i == total) {
        std::stringstream ss;
        ss << code;
        error = "Unknown error " + ss.str();
    }
}

//------------------------------------------------------------------------------
