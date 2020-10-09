#include <ecdh.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <sgx_cryptoall.h>
#ifdef ENCLAVED
#include <libc_mock/libcpp_mock.h>
#else
#include <iostream>
#endif

//------------------------------------------------------------------------------
const int ECDH::curve = NID_X9_62_prime256v1;
//------------------------------------------------------------------------------
ECDH::ECDH() : keypair_(nullptr), peer_pubkey_(nullptr) { generate_keypair(); }
//------------------------------------------------------------------------------
ECDH::~ECDH() {
    EVP_PKEY_free(keypair_);
    EVP_PKEY_free(peer_pubkey_);
}

//------------------------------------------------------------------------------
int ECDH::error_print(const char *str, size_t len, void *u) {
    std::cerr << std::string(str, len);
}

//------------------------------------------------------------------------------
void ECDH::print_sslerror() { ERR_print_errors_cb(ECDH::error_print, NULL); }

//------------------------------------------------------------------------------
void ECDH::generate_keypair() {
    EVP_PKEY *params = nullptr;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), *kctx;
    if (pctx == nullptr) print_sslerror();
    if (1 != EVP_PKEY_paramgen_init(pctx)) print_sslerror();
    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve))
        print_sslerror();
    if (!EVP_PKEY_paramgen(pctx, &params)) print_sslerror();
    if (nullptr == (kctx = EVP_PKEY_CTX_new(params, nullptr))) print_sslerror();
    if (1 != EVP_PKEY_keygen_init(kctx)) print_sslerror();
    if (1 != EVP_PKEY_keygen(kctx, &keypair_)) print_sslerror();
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(pctx);
}

//------------------------------------------------------------------------------
std::vector<uint8_t> ECDH::derive_shared_key() {
    EVP_PKEY_CTX *ctx;
    std::vector<uint8_t> secret;
    size_t secret_len;

    if (nullptr == (ctx = EVP_PKEY_CTX_new(keypair_, nullptr)))
        print_sslerror();
    if (1 != EVP_PKEY_derive_init(ctx)) print_sslerror();
    if (1 != EVP_PKEY_derive_set_peer(ctx, peer_pubkey_)) print_sslerror();
    if (1 != EVP_PKEY_derive(ctx, nullptr, &secret_len)) print_sslerror();
    secret.resize(secret_len);
    if (1 != (EVP_PKEY_derive(ctx, secret.data(), &secret_len)))
        print_sslerror();

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_pubkey_);
    EVP_PKEY_free(keypair_);
    peer_pubkey_ = keypair_ = nullptr;

    return Crypto::sha256(secret);
}

//------------------------------------------------------------------------------
// Extracts the pub key from EVP_PKEY and turns it into bytes
//------------------------------------------------------------------------------
std::vector<uint8_t> ECDH::pubkey_serialize() {
    EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(keypair_);
    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    const EC_POINT *ecpoint = EC_KEY_get0_public_key(eckey);
    point_conversion_form_t form = EC_KEY_get_conv_form(eckey);
    BN_CTX *bnctx = BN_CTX_new();
    size_t n = EC_POINT_point2oct(group, ecpoint, form, NULL, 0, bnctx);
    std::vector<uint8_t> ret(n, 0);
    EC_POINT_point2oct(group, ecpoint, form, ret.data(), ret.size(), bnctx);
    BN_CTX_free(bnctx);
    EC_KEY_free(eckey);
    return ret;
}

//------------------------------------------------------------------------------

/*int main() {
    ECDH e1, e2;
    e1.peer_pubkey(e2.pubkey_serialize());
    e2.peer_pubkey(e1.pubkey_serialize());
    std::vector<uint8_t> key1 = e1.derive_shared_key(),
                         key2 = e2.derive_shared_key();
    std::cout << (key1 == key2 ? "Yeah" : "Oops") << "\n"
              << "Key size: " << key1.size() << "\nFirst byte: 0x" << std::hex
              << (int)key1[0] << " == 0x" << (int)key2[0] << std::endl;
}//*/
