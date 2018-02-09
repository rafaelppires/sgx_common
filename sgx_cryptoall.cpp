#include "sgx_cryptoall.h"

#ifdef ENCLAVED
#include <sgx_tcrypto.h>
//#include <sgx_key.h>
#include <sgx_tseal.h>
#include <libc_mock/libcpp_mock.h>
#endif

#ifdef SGX_OPENSSL          // openssl {
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#elif defined( ENCLAVED )   // } openssl else sgx {
// maybe ipp stuff
#else                       // } sgx else crypto++ {
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
#endif                      // } crypto++

//------------------------------------------------------------------------------
#ifdef ENCLAVED
static int seal_common( uint16_t policy, 
                        const uint8_t *src, size_t srclen, void **sealed ) {
    std::string mactxt;
    size_t sz;
    if( (sz = sgx_calc_sealed_data_size(mactxt.size(),srclen)) == 0xFFFFFFFF )
        return -1;

    *sealed = malloc( sz ); // warning: caller frees it
    sgx_attributes_t attr;
    attr.flags = 0xFF0000000000000BULL;
    attr.xfrm  = 0;
    if( sgx_seal_data_ex( policy, attr, 0xF0000000, 0, NULL, srclen, src, 
                            sz, (sgx_sealed_data_t*)*sealed ) != SGX_SUCCESS ) {
        free( *sealed );
        *sealed = 0;
        return -2;
    }
    return sz;
}

int seal_signer ( const uint8_t *src, size_t srclen, void **sealed ) {
    seal_common( SGX_KEYPOLICY_MRSIGNER, src, srclen, sealed );

}

int seal_enclave( const uint8_t *src, size_t srclen, void **sealed ) {
    seal_common( SGX_KEYPOLICY_MRENCLAVE, src, srclen, sealed );
}

extern "C" { extern int printf(const char*,...); }
int unseal( const uint8_t *src, void **unsealed, 
            void **mactxt, size_t *txt_len ) {
    void *mactxt_aux = 0;
    uint32_t mactxt_len =sgx_get_add_mac_txt_len((const sgx_sealed_data_t*)src),
            decryp_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t*)src);

    *unsealed = malloc( decryp_len );
    if( txt_len == 0 ) mactxt = 0;
    if( mactxt )
        *mactxt = malloc( mactxt_len );
    else {
        mactxt = &mactxt_aux;
        mactxt_len = 0;
    }

    if( sgx_unseal_data( (const sgx_sealed_data_t*)src, 
                         (uint8_t*)*mactxt, &mactxt_len, 
                         (uint8_t*)*unsealed, &decryp_len ) != SGX_SUCCESS ) {
        free( *unsealed );
        free( *mactxt );
        *unsealed = *mactxt = 0;
        return -1;
    }

    *unsealed = realloc( *unsealed, decryp_len );
    if( *mactxt ) {    
        *mactxt   = realloc( *mactxt, mactxt_len );
        *txt_len  = mactxt_len;
    }
    return decryp_len;
}
#endif
//------------------------------------------------------------------------------
int encrypt_aes( char type, const uint8_t *plain, uint8_t *cipher, size_t plen,
                 const uint8_t *key, uint8_t *iv ) {
    int ret = 0;
#ifdef SGX_OPENSSL          //     openssl {
    int len;
    int cipher_len;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if( type == AES128 )
        EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    else if( type == AES256 )
        EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    else {
        ret = -1;
        goto getout;
    }
    EVP_EncryptUpdate(ctx, cipher, &len, plain, plen);
    cipher_len = len;
    EVP_EncryptFinal_ex(ctx, cipher + len, &len);
    cipher_len += len;
getout:
    EVP_CIPHER_CTX_free(ctx);
#elif defined( ENCLAVED ) //     } openssl else intel sdk { 
    uint8_t i[16];
    memcpy(i,iv,16); // intel's aes updates iv assuming `src` is a stream chunk
    if( type != AES128 ) // not supported by intel sdk
        ret = -1;
    else if( SGX_SUCCESS ==
               sgx_aes_ctr_encrypt((uint8_t(*)[16])key, plain, plen, i, 128, cipher) )
        ret = plen;
    else
        ret = -2;
#else                       //     } intel sdk else crypto++ {
try{
    size_t ksz = type == AES128 ? 16 : (type == AES256 ? 32 : 0);
    CTR_Mode< AES >::Encryption e;
    std::string cphr, pl((const char*)plain,plen);
    if( !ksz ){ ret = -1; goto getout; }
    e.SetKeyWithIV( key, ksz, iv );
    StringSource( pl, true, new StreamTransformationFilter(e,
                                                       new StringSink(cphr)));
    memcpy(cipher, cphr.c_str(), ret = std::min(plen,cphr.size()));
}   catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

getout:
#endif                      //     } crypto++
    return ret;
}

//------------------------------------------------------------------------------
int decrypt_aes( char type, const uint8_t *cipher, uint8_t *plain, size_t clen,
                 const uint8_t *key, uint8_t *iv ) {
    int ret = 0;
#ifdef SGX_OPENSSL          //     openssl {
    EVP_CIPHER_CTX *ctx;
    int len;
    ctx = EVP_CIPHER_CTX_new();
    if( type == AES128 )
        EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    else if( type == AES256 )
        EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    else {
        ret = -1; 
        goto getout;
    }
    EVP_DecryptUpdate(ctx, plain, &len, cipher, clen);
    ret = len;
    EVP_DecryptFinal_ex(ctx, (plain) + len, &len);
    ret += len;
getout:
    EVP_CIPHER_CTX_free(ctx);
#elif defined( ENCLAVED ) //     } openssl else intel sdk { 
    if( type != AES128 ) // not supported by intel sdk
        ret = -1;
    else if( SGX_SUCCESS ==
       sgx_aes_ctr_decrypt( (uint8_t(*)[16])key, cipher, clen, iv, 128, plain ))
        ret = clen;
    else
        ret = -2;
#else                       //     } intel sdk else crypto++ {
    size_t ksz = type == AES128 ? 16 : (type == AES256 ? 32 : 0);
    CTR_Mode< AES >::Decryption d;
    std::string recov, ciph((const char*)cipher,clen);
    if( !ksz ){ ret = -1; goto getout; }
    d.SetKeyWithIV( key, ksz, iv );
    StringSource( ciph, true, new StreamTransformationFilter(d,
                                                        new StringSink(recov)));
    memcpy(plain, recov.c_str(), ret = std::min(clen,recov.size()));
getout:
#endif                      //     } crypto++
    return ret;
}

//------------------------------------------------------------------------------
extern "C" { int printf( const char *f, ... ); }
int encrypt_rsa( const uint8_t* plaintext, size_t plain_len,
                 char* key, uint8_t* ciphertext, size_t cipher_len ) {
#ifdef ENCLAVED
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
#ifdef ENCLAVED
std::string sealSigner( const std::string &src ) {
    std::string ret;
    void *sealed;
    size_t sz;
    if( (sz = seal_signer( (const uint8_t*)src.c_str(), src.size(), &sealed )) 
                                                                         > 0 ) {
        ret = std::string( (char*)sealed, sz );
        free( sealed );
    }
    return ret;
}

std::string sealEnclave( const std::string &src ) {
    std::string ret;
    void *sealed;
    size_t sz;
    if( (sz = seal_enclave( (const uint8_t*)src.c_str(), src.size(), &sealed ))
                                                                         > 0 ) {
        ret = std::string( (char*)sealed, sz );
        free( sealed );
    }
    return ret;
}

std::string unseal( const std::string &src ) {
    std::string ret;
    void *unsealed;
    int len = ::unseal( (const uint8_t*)src.c_str(), &unsealed, 0, 0 );
    if( len > 0 ) {
        ret = std::string( (const char*)unsealed, len );
        free( unsealed );
    }
    return ret;
}
#endif

//------------------------------------------------------------------------------
#if !defined(ENCLAVED) && !defined(SGX_OPENSSL)
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
#if !defined(ENCLAVED) && !defined(SGX_OPENSSL)
    ByteQueue queue;
    key.Save(queue);
    SaveBase64(filename, queue);
#endif
}
//------------------------------------------------------------------------------
void SaveBase64PublicKey(const std::string& filename, const PubKey& key) {
#if !defined(ENCLAVED) && !defined(SGX_OPENSSL)
    ByteQueue queue;
    key.Save(queue);
    SaveBase64(filename, queue);
#endif
}
//------------------------------------------------------------------------------
void decodeBase64PrivateKey(const std::string& filename, PrvKey& key) {
#if !defined(ENCLAVED) && !defined(SGX_OPENSSL)
    Base64Decoder decoder;
    Decode(filename, decoder);
    decoder.MessageEnd();
    key.Load(decoder);
#endif
}
//------------------------------------------------------------------------------
void decodeBase64PublicKey(const std::string& filename, PubKey& key) {
#if !defined(ENCLAVED) && !defined(SGX_OPENSSL)
    Base64Decoder decoder;
    Decode(filename, decoder);
    decoder.MessageEnd();
    key.Load(decoder);
#endif
}
//------------------------------------------------------------------------------
void generateKeysAndSave() {
#if !defined(ENCLAVED) && !defined(SGX_OPENSSL)
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
    std::string ret, orep = " [+", crep = "] ";
    bool h = false;
    size_t count = 0;
    char last;
    for(std::string::const_iterator it=s.begin();it!=s.end(); ++it) {
        if( isasciigraph(*it) ) {
            if( h ) { ret += "\033[0m"; h = false; }
            if( count != 0 ) {
                ret += orep + std::to_string(count) + crep;
                count = 0;
            }
            ret += *it;
        } else {
            if( !h ) { ret += "\033[38;5;229m"; h = true; }
            //if( !ret.empty() && ret.at(ret.size()-1) == *it ) {
            //printf("%d %d\n", *it, ret[ret.size()-1] );
            if( !ret.empty() && last == *it ) {
                ++count;
            } else {
                if( count != 0 ) {
                    ret += orep + std::to_string(count) + crep;
                    count = 0; 
                }
                ret += hexchar(*it);
            }
        }
        last = *it;
    }
    if( count != 0 ) ret += orep + std::to_string(count) + crep;
    if( h ) ret += "\033[0m";;
    return ret;
}
//------------------------------------------------------------------------------
std::string encrypt_aes( const std::string &k, const std::string &plain ) {
    std::string cipher;
    unsigned char key[32], iv[16];
#if !defined(ENCLAVED) && !defined(SGX_OPENSSL)
    try {
        memset(key, 0, sizeof(key));
        memset(iv, 0, sizeof(iv));

        memcpy( key, k.c_str(), std::min(sizeof(key), k.size()) );
        for( uint8_t i = 0; i < sizeof(iv); i += sizeof(int) ) 
            *(int*)&iv[i] = rand();

        //key[0] = 'a'; key[15] = '5';
        //iv[0] = 'x'; iv[15] = '?';

        //std::cout << "plain text: " << plain << std::endl;

        CTR_Mode< AES >::Encryption e;
        e.SetKeyWithIV(key, k.size() > 16 ? 32 : 16, iv);

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
    return std::string((const char*)iv,sizeof(iv)) + cipher;
}

//------------------------------------------------------------------------------
void encrypt_aes_inline( const std::string &key, std::string &plain ) {
#ifndef ENCLAVED
    plain = encrypt_aes(key,plain);
#endif
}

//------------------------------------------------------------------------------
void decrypt_aes_inline( const std::string &key, std::string &cipher ) {
#ifndef ENCLAVED
    cipher = decrypt_aes(key, cipher);
#endif
}

//------------------------------------------------------------------------------
std::string decrypt_aes( const std::string &k, const std::string &cipher ) {
    std::string plain;
#if !defined(ENCLAVED) && !defined(SGX_OPENSSL)
    if( cipher.size() > 16 )
    try {
        byte key[32], iv[16];
        memset(key, 0, sizeof(key));
        memset(iv, 0, sizeof(iv));
        memcpy(key, k.c_str(), std::min(k.size(),sizeof(key)));
        memcpy(iv, cipher.c_str(), sizeof(iv));

        CTR_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, k.size() > 16 ? 32 : 16, iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(cipher.substr(sizeof(iv)), true,
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
#if !defined(ENCLAVED) && !defined(SGX_OPENSSL)
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
#if !defined(ENCLAVED) && !defined(SGX_OPENSSL)
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
#if !defined(ENCLAVED) && !defined(SGX_OPENSSL)
    CryptoPP::SHA256 hash;
    StringSource foo( data, true,
        new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(digest))
    );
#else
    uint8_t hash[32];
#ifdef ENCLAVED // intel
    sgx_sha256_msg( (const uint8_t*)data.c_str(), data.size(), &hash);
#else // openssl
    SHA256((const uint8_t*)data.c_str(), data.size(), hash);
#endif
    digest = std::string((char*)hash,32);
#endif
    return digest;
}

//------------------------------------------------------------------------------
std::string b64_encode( const std::string &data ) {
    std::string ret;
#if !defined(ENCLAVED) && !defined(SGX_OPENSSL)
    StringSource ssrc( data, true /*pump all*/,
                       new Base64Encoder( new StringSink(ret) ) );
#endif
    return ret;
}

//------------------------------------------------------------------------------
std::string b64_decode( const std::string &data ) {
    std::string ret;
#if !defined(ENCLAVED) && !defined(SGX_OPENSSL)
    StringSource ssrc( data, true /*pump all*/,
                       new Base64Decoder( new StringSink(ret) ) );
#endif
    return ret;
}

//------------------------------------------------------------------------------
} // namespace Crypto
