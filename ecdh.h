#pragma once

#include <openssl/evp.h>
#include <vector>

class ECDH {
   public:
    ECDH();
    ~ECDH();
    std::vector<uint8_t> derive_shared_key();
    std::vector<uint8_t> pubkey_serialize();
    void peer_pubkey(const std::vector<uint8_t> &);

   private:
    static const int curve;
    void generate_keypair();
    void print_sslerror();
    static int error_print(const char *str, size_t len, void *u);
    EVP_PKEY *keypair_, *peer_pubkey_;
};
