#ifndef _CRYPTO_ALL_H_
#define _CRYPTO_ALL_H_

#include <string>

#ifdef ENABLE_SGX
#include <sgx_tcrypto.h>
#endif

#if defined(__cplusplus) && !defined(ENABLE_SGX)
#include <crypto++/rsa.h>
#include <crypto++/aes.h>
#include <crypto++/ccm.h>
#include <crypto++/filters.h>

using CryptoPP::AES;
using CryptoPP::CTR_Mode;
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::StreamTransformationFilter;
#endif // cpp && !sgx

#if defined(__cplusplus)
namespace Crypto {

#ifndef ENABLE_SGX
typedef CryptoPP::RSA::PublicKey PubKey;
typedef CryptoPP::RSA::PrivateKey PrvKey;
#else
typedef int PubKey; // temporary
typedef int PrvKey; // temporary
#endif

std::string encrypt_aes( const std::string &plain );
void encrypt_aes_inline( std::string & );
void decrypt_aes_inline( std::string & );
std::string decrypt_aes( const std::string &cipher );
std::string encrypt_rsa( const PubKey &pubkey, const std::string &plain );
std::string decrypt_rsa( const PrvKey &prvkey, const std::string &cipher );
std::string printable( const std::string &s );
void decodeBase64PublicKey(const std::string& filename, PubKey& key);
void decodeBase64PrivateKey(const std::string& filename, PrvKey& key);
std::string sha256( const std::string& );
std::string base64( const std::string& );

}
#endif // cpp

//------------------------------------------------------------------------------
inline bool isspace( uint8_t c ) {
    return c >= 0x09 && c <= 0x0D;
}

//------------------------------------------------------------------------------
inline bool isasciigraph( uint8_t c ) {
    return c >= 0x20 && c <= 0x7E;
}

//------------------------------------------------------------------------------
inline const char* hexchar( uint8_t c ) {
    static std::string hex = "0123456789ABCDEF";
    static char ret[3];
    ret[0] = hex[ (c>>4) % hex.size() ];
    ret[1] = hex[ (c&0xF) % hex.size() ];
    ret[2] = 0;
    return ret;
}

//------------------------------------------------------------------------------
inline bool isgraphorspace( unsigned char c ) {
    return isspace(c) || isasciigraph(c) || (c >= 0x80 && c <= 0xFE);
}

//------------------------------------------------------------------------------
//extern "C" { extern int printf( const char *fmt, ... ); }
inline bool is_cipher( const uint8_t *buff, size_t len ) {
    for( size_t i = 0; i < len; ++i ) {
        if( !isgraphorspace(buff[i]) ) {
//            printf("%02hhd '%c' not recognized as graph or space\n", buff[i],buff[i]);
            return true;
        } else {
//            printf("=> %02X '%c'\n",buff[i],buff[i]);
        }
    }
    return false;
}

//------------------------------------------------------------------------------
inline void decrypt_aes128( const uint8_t *src, uint8_t *dst,  size_t len,
                            const uint8_t *key, uint8_t *iv ) {
#ifdef ENABLE_SGX
    sgx_aes_ctr_decrypt((uint8_t(*)[16])key, src, len, iv, 128, dst);
#else
    CTR_Mode< AES >::Decryption d;
    std::string recov, cipher((const char*)src,len);
    d.SetKeyWithIV( key, sizeof(key), iv );
    StringSource( cipher, true, new StreamTransformationFilter(d,
                                                       new StringSink(recov)));
    memcpy(dst, recov.c_str(), std::min(len,recov.size()));
#endif
}
//------------------------------------------------------------------------------
inline void encrypt_aes128( const uint8_t *src, uint8_t *dst, size_t len,
                            const uint8_t *key, uint8_t *iv ) {
#ifdef ENABLE_SGX
    uint8_t i[16];
    memcpy(i,iv,16); // sgx updates iv assuming `src` is a stream chunk
    sgx_aes_ctr_encrypt((uint8_t(*)[16])key, src, len, i, 128, dst);
#else
    CTR_Mode< AES >::Encryption e;
    std::string cipher, plain((const char*)src,len);
    e.SetKeyWithIV( key, sizeof(key), iv );
    StringSource( plain, true, new StreamTransformationFilter(e,
                                                       new StringSink(cipher)));
    memcpy(dst, cipher.c_str(), std::min(len,cipher.size()));
#endif
}

#endif // .h

