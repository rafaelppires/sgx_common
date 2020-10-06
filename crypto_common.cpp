#include <crypto_common.h>
#ifdef ENCLAVED
#include <sgx_trts.h>
#else
#include <stdlib.h>
#endif

//------------------------------------------------------------------------------
std::vector<uint8_t> get_rand(size_t len) {
    std::vector<uint8_t> ret(len, 0);
#ifdef ENCLAVED
    sgx_read_rand(ret.data(), ret.size());
#else
    for (size_t i = 0; i < ret.size(); i += sizeof(int))
        *(int *)&ret[i] = rand();
#endif
    return ret;
}

//------------------------------------------------------------------------------
