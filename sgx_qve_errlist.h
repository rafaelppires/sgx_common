#pragma once

#include <sgx_qve_header.h>
#include <string>

typedef struct _sgx_qve_errlist_t {
    sgx_ql_qv_result_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_qve_errlist_t;

extern sgx_qve_errlist_t sgx_qve_errlist[];
void qve_retrieve_error(sgx_ql_qv_result_t, std::string &, std::string &);
