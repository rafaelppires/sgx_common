#include <sgx_qe_errlist.h>

//------------------------------------------------------------------------------
sgx_qe_errlist_t sgx_qe_errlist[] = {
    {SGX_QL_SUCCESS, "Successfully calculated the required quote size.",
     "The required size in bytes is returned in the memory pointed to by "
     "p_quote_size."},
    {SGX_QL_ERROR_UNEXPECTED, "Unexpected internal erroroccurred.", nullptr},
    {SGX_QL_ERROR_INVALID_PARAMETER, "Invalid parameter.", NULL},
    {SGX_QL_ATT_KEY_NOT_INITIALIZED,
     "Platform quoting infrastructure does not have the attestation key "
     "available to generate quotes.",
     "Call sgx_qe_get_target_info() again."},
    {SGX_QL_ATT_KEY_CERT_DATA_INVALID,
     "Data returned by the platform quote provider library’s "
     "sgx_ql_get_quote_config() isinvalid",
     "(see section Platform Quote Provider Library)."},
    {SGX_QL_OUT_OF_EPC,
     "Not enough EPC memory to load one of the quote library enclavesneeded to "
     "complete this operation.",
     nullptr},
    {SGX_QL_ERROR_OUT_OF_MEMORY,
     "Heap memory allocation erroroccurredinalibrary or an enclave.", nullptr},
    {SGX_QL_ENCLAVE_LOAD_ERROR,
     "Unable to load one of the quote library enclaves required to initialize "
     "the attestation key.",
     "Could be due to file I/O erroror some other loading infrastructure "
     "errors."},
    {SGX_QL_ENCLAVE_LOST,
     "Enclave is lost after power transition or used in a child process "
     "created by linux fork().",
     nullptr},
    {SGX_QL_ATT_KEY_CERT_DATA_INVALID,
     "Certificationdata retrieved from the platform quote provider library is "
     "invalid.",
     nullptr},
    {SGX_QL_NO_PLATFORM_CERT_DATA,
     "The platform quote provider library doesn't have the platform "
     "certification datafor this platform.",
     nullptr},
    {SGX_QL_NO_DEVICE, "Can't open SGX device.",
     "This error happens only when running in out-of-process mode."},
    {SGX_QL_SERVICE_UNAVAILABLE,
     "Indicates AESM didn't respond or the requested service is not supported.",
     " This error happens only when running in out-of-process mode."},
    {SGX_QL_NETWORK_FAILURE,
     "Network connectionor proxy setting issue is encountered.",
     "This error happens only when running in out-of-process mode."},
    {SGX_QL_SERVICE_TIMEOUT,
     "The request to out-of-process service has timed out.",
     " This error happens only when running in out-of-process mode."},
    {SGX_QL_ERROR_BUSY, "The requested service is temporarily not available.",
     " This error happens only when running in out-of-process mode."},
    {SGX_QL_UNSUPPORTED_ATT_KEY_ID, "Unsupported attestation key ID.", nullptr},
    {SGX_QL_UNKNOWN_MESSAGE_RESPONSE,
     "Unexpected error from the attestation infrastructure while retrieving "
     "the platform data.",
     nullptr},
    {SGX_QL_ERROR_MESSAGE_PARSING_ERROR,
     "Generic message parsing error from the attestation infrastructure while "
     "retrieving the platform data.",
     nullptr},
    {SGX_QL_PLATFORM_UNKNOWN, "This platform is an unrecognized SGX platform.",
     nullptr}};

//------------------------------------------------------------------------------
void retrieve_error_msg(quote3_error_t code, std::string &error,
                        std::string &extra) {
    size_t i, total = sizeof sgx_qe_errlist / sizeof sgx_qe_errlist[0];
    for (i = 0; i < total; ++i) {
        if (code == sgx_qe_errlist[i].err) {
            if (sgx_qe_errlist[i].msg != nullptr) error = sgx_qe_errlist[i].msg;
            if (sgx_qe_errlist[i].sug != nullptr) extra = sgx_qe_errlist[i].sug;
            break;
        }
    }
    if (i == total) {
        error = "Unknown error " + std::to_string(code);
    }
}

//------------------------------------------------------------------------------
