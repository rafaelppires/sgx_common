#ifndef _CRYPTO_ALL_H_
#define _CRYPTO_ALL_H_

#include <string>

#if defined(__cplusplus) && !defined(ENCLAVED) // cxx && !sgx {
#include <crypto++/rsa.h>
#endif // } cxx && !sgx

#if defined(__cplusplus)
namespace Crypto {

#ifdef ENCLAVED
typedef int PubKey; // temporary
typedef int PrvKey; // temporary
#else
typedef CryptoPP::RSA::PublicKey PubKey;
typedef CryptoPP::RSA::PrivateKey PrvKey;
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

#ifdef ENCLAVED
std::string sealEnclave( const std::string &src );
std::string sealSigner( const std::string &src );
#endif
}

extern "C" {
#endif // cpp

#define AES128 1
#define AES256 2
int decrypt_aes( char type, const uint8_t *src, uint8_t *dst,  size_t len,
                 const uint8_t *key, uint8_t *iv );
int encrypt_aes( char type, const uint8_t *src, uint8_t *dst, size_t len,
                  const uint8_t *key, uint8_t *iv );
int encrypt_rsa( const uint8_t* plaintext, size_t plain_len,
                 char* key, uint8_t* ciphertext, size_t cipher_len);
#ifdef ENCLAVED
int seal_signer ( const uint8_t *src, size_t srclen, void **sealed );
int seal_enclave( const uint8_t *src, size_t srclen, void **sealed );
#endif

#ifdef ENCLAVED
//------------------------------------------------------------------------------
inline bool isspace( uint8_t c ) {
    return c >= 0x09 && c <= 0x0D;
}
#endif

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

#if defined(__cplusplus)
}
#endif

#endif // .h

