#pragma once

#include <sgx_dcap_ql_wrapper.h>
#include <string>

typedef struct _sgx_qv_errlist_t {
    quote3_error_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_qv_errlist_t;

extern sgx_qv_errlist_t sgx_qv_errlist[];
void qv_retrieve_error(quote3_error_t, std::string &, std::string &);
