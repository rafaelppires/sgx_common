#include <crypto_common.h>
#ifdef ENCLAVED
#include <sgx_trts.h>
#endif

//------------------------------------------------------------------------------
std::string get_rand(size_t len) {
    unsigned char r[len];
#ifdef ENCLAVED
    sgx_read_rand(r, len);
#else
    for (size_t i = 0; i < len; i += sizeof(int)) *(int *)&r[i] = rand();
#endif
    return std::string((char *)r, len);
}

//------------------------------------------------------------------------------
