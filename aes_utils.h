#pragma once

//------------------------- C compatble ----------------------------------------
#if defined(__cplusplus)
#include <string>
extern "C" {
#endif

#define AES128 1
#define AES256 2
int decrypt_aes(char type, const uint8_t *src, uint8_t *dst, size_t len,
                const uint8_t *key, uint8_t *iv);
int encrypt_aes(char type, const uint8_t *src, uint8_t *dst, size_t len,
                const uint8_t *key, uint8_t *iv);
void encrypt_aes_gcm(const uint8_t *plain, int in_len, uint8_t *ciphertext,
                     uint8_t *tag, const uint8_t *key, const uint8_t *iv);
int decrypt_aes_gcm(const uint8_t *ciphertext, int in_len, uint8_t *decrypted,
                    const uint8_t *tag, const uint8_t *key, const uint8_t *iv);

#if defined(__cplusplus)
}
#endif

//------------------------------------------------------------------------------
#if defined(__cplusplus)
namespace Crypto {

std::string encrypt_aes(const std::string &key, const std::string &plain);
std::string decrypt_aes(const std::string &key, const std::string &cipher);

void encrypt_aes_inline(const std::string &key, std::string &plain);
void decrypt_aes_inline(const std::string &key, std::string &);

template <typename T>
T encrypt_aesgcm(const T &key, const T &plain);
template <typename Key, typename Data>
std::pair<bool, std::vector<uint8_t>> decrypt_aesgcm(const Key &key,
                                                     const Data &cipher);
}  // namespace Crypto

#include "aes_utils.hpp"
#endif
//------------------------------------------------------------------------------
