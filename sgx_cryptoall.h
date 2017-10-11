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

namespace Crypto {

typedef CryptoPP::RSA::PublicKey PubKey;
typedef CryptoPP::RSA::PrivateKey PrvKey;

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
#endif // cpp && !sgx

//------------------------------------------------------------------------------
inline bool isgraphorspace( char cc ) {
    unsigned char c = cc;
    return (c >= 0x09 && c <= 0x0D) || (c >= 0x20 && c <= 0x7E ) ||
           (c >= 0x80 && c <= 0xFE);
}

//------------------------------------------------------------------------------
inline bool is_cipher( const char *buff, size_t len ) {
    for( size_t i = 0; i < len; ++i )
        if( !isgraphorspace(buff[i]) ) {
            //printf("%02hhd '%c' not recognized as graph or space\n", buff[i],buff[i]);
            return true;
        }
    return false;
}

//------------------------------------------------------------------------------
inline void decrypt( const char *src, char *dst,  size_t len ) {
    uint8_t key[16], iv[16];
    memset(key,0,16); memset(iv,0,16);
    key[0] = 'a'; key[15] = '5';
    iv[0] = 'x'; iv[15]= '?';
#ifdef ENABLE_SGX
    sgx_aes_ctr_decrypt(&key, (const uint8_t*)src, len, iv, 128, (uint8_t*)dst);
#else
    CTR_Mode< AES >::Decryption d;
    std::string recov, cipher(src,len);
    d.SetKeyWithIV( key, sizeof(key), iv );
    StringSource( cipher, true, new StreamTransformationFilter(d,
                                                       new StringSink(recov)));
    memcpy(dst, recov.c_str(), std::min(len,recov.size()));
#endif
}
//------------------------------------------------------------------------------
inline void encrypt( const char *src, char *dst, size_t len ) {
    uint8_t key[16], iv[16];
    memset(key,0,16); memset(iv,0,16);
    key[0] = 'a'; key[15] = '5';
    iv[0] = 'x'; iv[15]= '?';
#ifdef ENABLE_SGX
    sgx_aes_ctr_encrypt(&key, (const uint8_t*)src, len, iv, 128, (uint8_t*)dst);
#else
    CTR_Mode< AES >::Encryption e;
    std::string cipher, plain(src,len);
    e.SetKeyWithIV( key, sizeof(key), iv );
    StringSource( plain, true, new StreamTransformationFilter(e,
                                                       new StringSink(cipher)));
    memcpy(dst, cipher.c_str(), std::min(len,cipher.size()));
#endif
}

#endif // .h

