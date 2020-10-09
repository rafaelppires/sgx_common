#pragma once

#include <openssl/evp.h>
#include <vector>

class ECDH {
   public:
    ECDH();
    ~ECDH();
    std::vector<uint8_t> derive_shared_key();
    std::vector<uint8_t> pubkey_serialize();
    template<typename T>
    void peer_pubkey(const T &);

   private:
    static const int curve;
    void generate_keypair();
    void print_sslerror();
    static int error_print(const char *str, size_t len, void *u);
    EVP_PKEY *keypair_, *peer_pubkey_;
};

#include <ecdh.hpp>

