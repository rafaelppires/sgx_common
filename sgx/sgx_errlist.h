#pragma once

#include <sgx_error.h>

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg; 
    const char *sug; /* Suggestion */
} sgx_errlist_t;

extern sgx_errlist_t sgx_errlist[];
void print_error_message(sgx_status_t ret);

