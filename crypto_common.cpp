#include <crypto_common.h>
#ifdef ENCLAVED
#include <sgx_trts.h>
#else
#include <stdlib.h>
#endif

//------------------------------------------------------------------------------
std::vector<uint8_t> get_rand(size_t len) {
    std::vector<uint8_t> ret(len, 0);
    get_rand_inline(len, ret.data());
    return ret;
}

//------------------------------------------------------------------------------
void get_rand_inline(size_t len, uint8_t *where) {
#ifdef ENCLAVED
    sgx_read_rand(where, len);
#else
    for (size_t i = 0; i < len; i += sizeof(int))
        *(int *)&where[i] = rand();
#endif
}

//------------------------------------------------------------------------------
