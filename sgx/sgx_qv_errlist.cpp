#include <sgx_qv_errlist.h>

//------------------------------------------------------------------------------
sgx_qv_errlist_t sgx_qv_errlist[] = {
    {SGX_QL_SUCCESS, "Successfully evaluated the quote.", nullptr},
    {SGX_QL_ERROR_INVALID_PARAMETER, "One of the input parameters value.",
     nullptr},
    {SGX_QL_QUOTE_FORMAT_UNSUPPORTED,
     "The inputted quote format is not supported.",
     "Either because the header information is not supported or the quote is "
     "malformed in some way."},
    {SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED,
     "The quote verifier doesn't support the certification data in the Quote.",
     "Currently, the Intel QVE only supported CertType = 5."},
    {SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT,
     "The quote verifier doesn't support the format of the application REPORT "
     "the Quote.",
     "SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT"},
    {SGX_QL_QE_REPORT_INVALID_SIGNATURE,
     "The signature over the QE Report is invalid.", nullptr},
    {SGX_QL_QEIDENTITY_MISMATCH, "SGX_QL_QEIDENTITY_MISMATCH", nullptr},
    {SGX_QL_ERROR_QVL_QVE_MISMATCH,
     "QvE returned supplemental data version mismatched between QVL and QvE",
     nullptr},
    {SGX_QL_QVEIDENTITY_MISMATCH,
     "QvE Identity is NOT match to Intel signed QvE identity", nullptr},
    {SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT,
     "The format of the PCK Cert is unsupported.", nullptr},
    {SGX_QL_PCK_CERT_CHAIN_ERROR,
     "There was an error verifying the PCK Cert signature chain including PCK "
     "Cert revocation.",
     nullptr},
    {SGX_QL_TCBINFO_UNSUPPORTED_FORMAT,
     "The format of the TCBInfo structureis unsupported.", nullptr},
    {SGX_QL_TCBINFO_CHAIN_ERROR,
     "There was an error verifying the TCBInfo signature chain including "
     "TCBInfo revocation.",
     nullptr},
    {SGX_QL_TCBINFO_MISMATCH,
     "PCK Cert FMSPc does not match the TCBInfo FMSPc.", nullptr},
    {SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT,
     "The format of the QEIdentity structureis unsupported.", nullptr},
    {SGX_QL_QEIDENTITY_MISMATCH,
     "The Quote's QE doesn't match the inputted expected QEIdentity.", nullptr},
    {SGX_QL_QEIDENTITY_CHAIN_ERROR,
     "There was an error verifying the QEIdentity signaturechainincluding "
     "QEIdentity revocation.",
     nullptr},
    {SGX_QL_ERROR_OUT_OF_MEMORY,
     "Heap memory allocation error in library or enclave.", nullptr},
    {SGX_QL_ENCLAVE_LOAD_ERROR,
     "Unable to load the enclaves required to initialize the attestation key.",
     "Could be due to file I / O error, loading infrastructure error or "
     "insufficient enclave memory."},
    {SGX_QL_ENCLAVE_LOST,
     "Enclave lost after power transition or used in child process created by "
     "linux fork()."},
    {SGX_QL_INVALID_REPORT, "Report MAC check failed on application report.",
     nullptr},
    {SGX_QL_PLATFORM_LIB_UNAVAILABLE,
     "The Quote Library could not locate the provider library.", nullptr},
    {SGX_QL_UNABLE_TO_GENERATE_REPORT,
     "The QVE was unable to generate its own report targeting the application "
     "enclave because there is an enclave compatibility issue.",
     nullptr},
    {SGX_QL_UNABLE_TO_GET_COLLATERAL,
     "The Quote Library was available but the quote library could not retrieve "
     "the data.",
     nullptr},
    {SGX_QL_ERROR_UNEXPECTED, " An unexpected internal error occurred.",
     nullptr}};

//------------------------------------------------------------------------------
void qv_retrieve_error(quote3_error_t code, std::string &error,
                       std::string &extra) {
    size_t i, total = sizeof sgx_qv_errlist / sizeof sgx_qv_errlist[0];
    for (i = 0; i < total; ++i) {
        if (code == sgx_qv_errlist[i].err) {
            if (sgx_qv_errlist[i].msg != nullptr) error = sgx_qv_errlist[i].msg;
            if (sgx_qv_errlist[i].sug != nullptr) extra = sgx_qv_errlist[i].sug;
            break;
        }
    }
    if (i == total) {
        error = "Unknown error " + std::to_string(code);
    }
}

//------------------------------------------------------------------------------
