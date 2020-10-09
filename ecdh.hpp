#include <openssl/ec.h>
//------------------------------------------------------------------------------
template <typename T>
void ECDH::peer_pubkey(const T &der_key) {
    EC_GROUP *group = EC_GROUP_new_by_curve_name(curve);
    EC_POINT *ecpoint = EC_POINT_new(group);
    BN_CTX *bnctx = BN_CTX_new();
    if (1 != EC_POINT_oct2point(group, ecpoint, (const uint8_t *)der_key.data(),
                                der_key.size(), bnctx))
        print_sslerror();
    EC_KEY *peerkey = EC_KEY_new();
    if (1 != (EC_KEY_set_group(peerkey, group))) print_sslerror();
    if (1 != EC_KEY_set_public_key(peerkey, ecpoint)) print_sslerror();
    peer_pubkey_ = EVP_PKEY_new();
    if (1 != EVP_PKEY_set1_EC_KEY(peer_pubkey_, peerkey)) print_sslerror();
    EC_KEY_free(peerkey);
    BN_CTX_free(bnctx);
    EC_POINT_free(ecpoint);
    EC_GROUP_free(group);
}

//------------------------------------------------------------------------------
