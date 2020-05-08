#ifndef _CRYPTO_ALL_H_
#define _CRYPTO_ALL_H_

#include <stdint.h>
#include <string>

#ifdef ENCLAVED
#include <sgx_tseal.h>
#endif

#if defined(__cplusplus)
namespace Crypto {

#if defined(ENCLAVED) || defined(USE_OPENSSL)
typedef int PubKey;  // temporary
typedef int PrvKey;  // temporary
#else
typedef CryptoPP::RSA::PublicKey PubKey;
typedef CryptoPP::RSA::PrivateKey PrvKey;
#endif

std::string encrypt_rsa(const PubKey &pubkey, const std::string &plain);
std::string decrypt_rsa(const PrvKey &prvkey, const std::string &cipher);
std::string printable(const std::string &s);
void decodeBase64PublicKey(const std::string &filename, PubKey &key);
void decodeBase64PrivateKey(const std::string &filename, PrvKey &key);
std::string sha256(const std::string &);
std::string sha224(const std::string &);
std::string b64_encode(const std::string &);
std::string b64_decode(const std::string &);
std::string hex_encode(const std::string &);
std::string get_rand(size_t);

#ifdef ENCLAVED
class StateSha256 {
   public:
    sgx_sha_state_handle_t context;
};

bool sha256_init(StateSha256 &s);
bool sha256_append(StateSha256 &s, const std::string &);
std::string sha256_get(StateSha256 &s);

#ifdef SGX_OPENSSL
class StateHmacSha256;
bool hmac_sha256_init(StateSha256 &ctx, const std::string &key);
bool hmac_sha256_append(StateSha256 &ctx, const std::string &data);
std::string hmac_sha256_get(StateSha256 &ctx);
#endif

std::string sha256(StateSha256 &s);
std::string sealEnclave(const std::string &src);
std::string sealSigner(const std::string &src);
std::string unseal(const std::string &src);
#endif
}  // namespace Crypto

extern "C" {
#endif  // cpp

int encrypt_rsa(const uint8_t *plaintext, size_t plain_len, char *key,
                uint8_t *ciphertext, size_t cipher_len);

#ifdef ENCLAVED
/** output buffers are all allocated inside these functions
    it is the caller's responsibility to free them
    return: the size of sealed or unsealed data */
int seal_signer(const uint8_t *src, size_t srclen, void **sealed /* out */);
int seal_enclave(const uint8_t *src, size_t srclen, void **sealed /* out */);
int unseal(const uint8_t *src /* in, len info is inside */,
           void **unsealed /* out, cannot be NULL */,
           void **mactxt /* out, optional - may be NULL */,
           size_t *txt_len /* out, optional - may be NULL */);
#endif

#ifdef ENCLAVED
#ifndef _LIBCPP_CCTYPE
//------------------------------------------------------------------------------
inline bool isspace(uint8_t c) { return c >= 0x09 && c <= 0x0D; }
#endif
#endif

//------------------------------------------------------------------------------
inline bool isasciigraph(uint8_t c) { return c >= 0x20 && c <= 0x7E; }

//------------------------------------------------------------------------------
inline const char *hexchar(uint8_t c) {
    // static std::string hex = "0123456789ABCDEF";
    static std::string hex = "0123456789abcdef";
    static char ret[3];
    ret[0] = hex[(c >> 4) % hex.size()];
    ret[1] = hex[(c & 0xF) % hex.size()];
    ret[2] = 0;
    return ret;
}

//------------------------------------------------------------------------------
inline bool isgraphorspace(unsigned char c) {
    return isspace(c) || isasciigraph(c) || (c >= 0x80 && c <= 0xFE);
}

//------------------------------------------------------------------------------
// extern "C" { extern int printf( const char *fmt, ... ); }
inline bool is_cipher(const uint8_t *buff, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (!isgraphorspace(buff[i])) {
            //            printf("%02hhd '%c' not recognized as graph or
            //            space\n", buff[i],buff[i]);
            return true;
        } else {
            //            printf("=> %02X '%c'\n",buff[i],buff[i]);
        }
    }
    return false;
}

//------------------------------------------------------------------------------

#if defined(__cplusplus)
}
#endif

#endif  // .h
