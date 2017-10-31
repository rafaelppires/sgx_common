#include "sgx_cryptoall.h"

#ifdef ENABLE_SGX           // sgx {
#ifdef SGX_OPENSSL          //     openssl {
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#endif                      //     } openssl
#else                       // } sgx
#include <fstream>
#include <iostream>
#include <crypto++/osrng.h>
#include <crypto++/cryptlib.h>
#include <crypto++/filters.h>
#include <cryptopp/files.h>
#include <crypto++/aes.h>
#include <crypto++/ccm.h>
#include <crypto++/base64.h>
#include <crypto++/queue.h>
#include <crypto++/hex.h>
using CryptoPP::Exception;
using CryptoPP::BufferedTransformation;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::FileSink;
using CryptoPP::FileSource;
using CryptoPP::AES;
using CryptoPP::CTR_Mode;
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;
using CryptoPP::ByteQueue;
#endif

//------------------------------------------------------------------------------
void encrypt_aes128( const uint8_t *plain, uint8_t *cipher, size_t plen,
                     const uint8_t *key, uint8_t *iv ) {
#ifdef ENABLE_SGX
#ifdef SGX_OPENSSL //     openssl {
    int len;
    int cipher_len;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
//    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, cipher, &len, plain, plen);
    cipher_len = len;
    EVP_EncryptFinal_ex(ctx, cipher + len, &len);
    cipher_len += len;
    EVP_CIPHER_CTX_free(ctx);
#else              //     } openssl else intel sdk { 
    uint8_t i[16];
    memcpy(i,iv,16); // intel's aes updates iv assuming `src` is a stream chunk
    sgx_aes_ctr_encrypt((uint8_t(*)[16])key, src, len, i, 128, dst);
#endif             //     } intel sdk
#else
    CTR_Mode< AES >::Encryption e;
    std::string cphr, pl((const char*)plain,plen);
    e.SetKeyWithIV( key, sizeof(key), iv );
    StringSource( plain, true, new StreamTransformationFilter(e,
                                                       new StringSink(cphr)));
    memcpy(cipher, cphr.c_str(), std::min(plen,cphr.size()));
#endif
}

//------------------------------------------------------------------------------
void decrypt_aes128( const uint8_t *cipher, uint8_t *plain,  size_t clen,
                     const uint8_t *key, uint8_t *iv ) {
#ifdef ENABLE_SGX  // sgx {
#ifdef SGX_OPENSSL //     openssl {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    ctx = EVP_CIPHER_CTX_new();
    //EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plain, &len, cipher, clen);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, (plain) + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
#else              //     } openssl else intel sdk { 
    sgx_aes_ctr_decrypt((uint8_t(*)[16])key, cipher, clen, iv, 128, plain);
#endif             //     } intel sdk
#else              // } sgx else crypto++ {
    CTR_Mode< AES >::Decryption d;
    std::string recov, ciph((const char*)cipher,clen);
    d.SetKeyWithIV( key, sizeof(key), iv );
    StringSource( ciph, true, new StreamTransformationFilter(d,
                                                        new StringSink(recov)));
    memcpy(plain, recov.c_str(), std::min(clen,recov.size()));
#endif             // } crypto++
}

//------------------------------------------------------------------------------
extern "C" { int printf( const char *f, ... ); }
int encrypt_rsa( const uint8_t* plaintext, size_t plain_len,
                 char* key, uint8_t* ciphertext, size_t cipher_len ) {
#ifdef ENABLE_SGX
#if 0
    BIO *bio_buffer = NULL;
    RSA *rsa = NULL;
printf("(1)%s\n",key);
    //bio_buffer = BIO_new_mem_buf((void*)key, /*-1*/strlen(key));
    char oi[] = "oi";
    bio_buffer = BIO_new_mem_buf((void*)oi, -1);
printf("(2)\n");
/*
    PEM_read_bio_RSA_PUBKEY(bio_buffer, &rsa, 0, NULL);
printf("(3)\n");
    size_t rsa_min = RSA_size( rsa );
    if( cipher_len < rsa_min ) {
        return -rsa_min;
    }
printf("(4)\n");

    int ciphertext_size = RSA_public_encrypt( plain_len, plaintext,
                                              ciphertext,
                                              rsa, RSA_PKCS1_PADDING );
printf("(5)\n");
    return ciphertext_size;
*/
#endif
    return 0;
#endif
}

//------------------------------------------------------------------------------
namespace Crypto {
//------------------------------------------------------------------------------
#ifndef ENABLE_SGX
void Save(const std::string& filename, const BufferedTransformation& bt) {
    FileSink file(filename.c_str());
    bt.CopyTo(file);
}
//------------------------------------------------------------------------------
void SaveBase64(const std::string& filename, const BufferedTransformation& bt) {
    Base64Encoder encoder;
    bt.CopyTo(encoder);
    encoder.MessageEnd();
    Save(filename, encoder);
}
//------------------------------------------------------------------------------
void Decode(const std::string& filename, BufferedTransformation& bt) {
    FileSource file(filename.c_str(), true /*pumpAll*/);
    file.TransferTo(bt);
    bt.MessageEnd();
}
#endif
//------------------------------------------------------------------------------
void SaveBase64PrivateKey(const std::string& filename, const PrvKey& key) {
#ifndef ENABLE_SGX
    ByteQueue queue;
    key.Save(queue);
    SaveBase64(filename, queue);
#endif
}
//------------------------------------------------------------------------------
void SaveBase64PublicKey(const std::string& filename, const PubKey& key) {
#ifndef ENABLE_SGX
    ByteQueue queue;
    key.Save(queue);
    SaveBase64(filename, queue);
#endif
}
//------------------------------------------------------------------------------
void decodeBase64PrivateKey(const std::string& filename, PrvKey& key) {
#ifndef ENABLE_SGX
    Base64Decoder decoder;
    Decode(filename, decoder);
    decoder.MessageEnd();
    key.Load(decoder);
#endif
}
//------------------------------------------------------------------------------
void decodeBase64PublicKey(const std::string& filename, PubKey& key) {
#ifndef ENABLE_SGX
    Base64Decoder decoder;
    Decode(filename, decoder);
    decoder.MessageEnd();
    key.Load(decoder);
#endif
}
//------------------------------------------------------------------------------
void generateKeysAndSave() {
#ifndef ENABLE_SGX
    CryptoPP::AutoSeededRandomPool rng;

    // Create Keys
    PrvKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 3072);

    PubKey publicKey(privateKey);
    SaveBase64PrivateKey( "key.prv", privateKey );
    SaveBase64PublicKey( "key.pub", publicKey );
#endif
}

//------------------------------------------------------------------------------
std::string printable( const std::string &s ) {
    std::string ret;
    bool h = false;
    for(std::string::const_iterator it=s.begin();it!=s.end(); ++it) {
        if( isasciigraph(*it) ) {
            if( h ) { ret += "\033[0m"; h = false; }
            ret += *it;
        } else {
            if( !h ) { ret += "\033[38;5;229m"; h = true; }
            ret += hexchar(*it);
        }
    }
    if( h ) ret += "\033[0m";;
    return ret;
}
//------------------------------------------------------------------------------
std::string encrypt_aes( const std::string &plain ) {
    std::string cipher;
#ifndef ENABLE_SGX
    try {
        byte key[16], iv[16];
        memset(key, 0, 16); memset(iv, 0, 16);
        key[0] = 'a'; key[15] = '5';
        iv[0] = 'x'; iv[15] = '?';

        //std::cout << "plain text: " << plain << std::endl;

        CTR_Mode< AES >::Encryption e;
        e.SetKeyWithIV(key, sizeof(key), iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(plain, true,
                   new StreamTransformationFilter(e, new StringSink(cipher) ) );
    } catch(const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
#endif
    return cipher;
}

//------------------------------------------------------------------------------
void encrypt_aes_inline( std::string &plain ) {
#ifndef ENABLE_SGX
    plain = encrypt_aes(plain);
#endif
}

//------------------------------------------------------------------------------
void decrypt_aes_inline( std::string &cipher ) {
#ifndef ENABLE_SGX
    cipher = decrypt_aes(cipher);
#endif
}

//------------------------------------------------------------------------------
std::string decrypt_aes( const std::string &cipher ) {
    std::string plain;
#ifndef ENABLE_SGX
    try {
        byte key[16], iv[16];
        memset(key, 0, 16); memset(iv, 0, 16);
        key[0] = 'a'; key[15] = '5';
        iv[0] = 'x'; iv[15] = '?';

        CTR_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, sizeof(key), iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(cipher, true,
                    new StreamTransformationFilter(d, new StringSink(plain) ) );
    } catch(const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
#endif
    return plain;
}

//------------------------------------------------------------------------------
std::string encrypt_rsa( const PubKey &pubkey, const std::string &plain ) {
    std::string cipher;
#ifndef ENABLE_SGX
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Encryptor e(pubkey);
    StringSource ss1( plain, true,
            new CryptoPP::PK_EncryptorFilter(rng, e, new StringSink(cipher) ) );
#endif
    return cipher;
}

//------------------------------------------------------------------------------
std::string decrypt_rsa( const PrvKey &prvkey, const std::string &cipher ) {
    std::string recovered;
#ifndef ENABLE_SGX
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Decryptor d(prvkey);

    StringSource ss( cipher, true,
         new CryptoPP::PK_DecryptorFilter(rng, d, new StringSink(recovered) ) );
#endif
    return recovered;
}

//------------------------------------------------------------------------------
std::string sha256( const std::string &data ) {
    std::string digest;
#ifndef ENABLE_SGX
    CryptoPP::SHA256 hash;
    StringSource foo( data, true,
        new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(digest))
    );
#else
    uint8_t hash[32];
    sgx_sha256_msg( (const uint8_t*)data.c_str(), data.size(), &hash);
    digest = std::string((char*)hash,32);
#endif
    return digest;
}

//------------------------------------------------------------------------------
std::string base64( const std::string &data ) {
    std::string ret;
#ifndef ENABLE_SGX
    StringSource ssrc( data, true /*pump all*/,
                       new Base64Encoder( new StringSink(ret) ) );
#endif
    return ret;
}

//------------------------------------------------------------------------------
} // namespace Crypto
