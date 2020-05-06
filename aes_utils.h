#pragma once


#if defined(__cplusplus)
#include <string>
namespace Crypto {

std::string encrypt_aes(const std::string &key, const std::string &plain);      
std::string decrypt_aes(const std::string &key, const std::string &cipher);     

void encrypt_aes_inline(const std::string &key, std::string &plain);            
void decrypt_aes_inline(const std::string &key, std::string &);                 

std::string encrypt_aesgcm(const std::string &key, const std::string &plain);   
std::pair<bool, std::string> decrypt_aesgcm(const std::string &key,             
                                            const std::string &cipher);
}
#endif

//------------------------- C compatble ----------------------------------------
#if defined(__cplusplus)
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
                    uint8_t *reftag, const uint8_t *key, const uint8_t *iv);

#if defined(__cplusplus)
}
#endif
//------------------------------------------------------------------------------
