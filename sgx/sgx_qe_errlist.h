#pragma once

#include <sgx_dcap_ql_wrapper.h>
#include <string>

typedef struct _sgx_qe_errlist_t {
    quote3_error_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_qe_errlist_t;

extern sgx_qe_errlist_t sgx_qe_errlist[];
void retrieve_error_msg(quote3_error_t, std::string &, std::string &);
