#include "sgx_cryptoall.h"
#include <algorithm>
#include <string.h>

#ifdef ENCLAVED
#include <libc_mock/libcpp_mock.h>
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
#endif

#ifdef USE_OPENSSL  // openssl {
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#elif defined(ENCLAVED)  // } openssl else sgx {
// maybe ipp stuff
#else                    // } sgx else crypto++ {
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/osrng.h>
#include <fstream>
#include <iostream>
using CryptoPP::AES;
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;
using CryptoPP::BufferedTransformation;
using CryptoPP::ByteQueue;
using CryptoPP::CTR_Mode;
using CryptoPP::Exception;
using CryptoPP::FileSink;
using CryptoPP::FileSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
#endif  // } crypto++

//------------------------------------------------------------------------------
#ifdef ENCLAVED
static int seal_common(uint16_t policy, const uint8_t *src, size_t srclen,
                       void **sealed) {
    std::string mactxt;
    size_t sz;
    if ((sz = sgx_calc_sealed_data_size(mactxt.size(), srclen)) == 0xFFFFFFFF)
        return -1;

    *sealed = malloc(sz);  // warning: caller frees it
    sgx_attributes_t attr;
    attr.flags = 0xFF0000000000000BULL;
    attr.xfrm = 0;
    if (sgx_seal_data_ex(policy, attr, 0xF0000000, 0, NULL, srclen, src, sz,
                         (sgx_sealed_data_t *)*sealed) != SGX_SUCCESS) {
        free(*sealed);
        *sealed = 0;
        return -2;
    }
    return sz;
}

int seal_signer(const uint8_t *src, size_t srclen, void **sealed) {
    return seal_common(SGX_KEYPOLICY_MRSIGNER, src, srclen, sealed);
}

int seal_enclave(const uint8_t *src, size_t srclen, void **sealed) {
    return seal_common(SGX_KEYPOLICY_MRENCLAVE, src, srclen, sealed);
}

extern "C" {
extern int printf(const char *, ...);
}
int unseal(const uint8_t *src, void **unsealed, void **mactxt,
           size_t *txt_len) {
    void *mactxt_aux = 0;
    uint32_t mactxt_len =
                 sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)src),
             decryp_len =
                 sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)src);

    *unsealed = malloc(decryp_len);
    if (txt_len == 0) mactxt = 0;
    if (mactxt)
        *mactxt = malloc(mactxt_len);
    else {
        mactxt = &mactxt_aux;
        mactxt_len = 0;
    }

    if (sgx_unseal_data((const sgx_sealed_data_t *)src, (uint8_t *)*mactxt,
                        &mactxt_len, (uint8_t *)*unsealed,
                        &decryp_len) != SGX_SUCCESS) {
        free(*unsealed);
        free(*mactxt);
        *unsealed = *mactxt = 0;
        return -1;
    }

    *unsealed = realloc(*unsealed, decryp_len);
    if (*mactxt) {
        *mactxt = realloc(*mactxt, mactxt_len);
        *txt_len = mactxt_len;
    }
    return decryp_len;
}
#endif

//------------------------------------------------------------------------------
extern "C" {
int printf(const char *f, ...);
}
int encrypt_rsa(const uint8_t *plaintext, size_t plain_len, char *key,
                uint8_t *ciphertext, size_t cipher_len) {
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
#endif
    return 0;
}

//------------------------------------------------------------------------------
namespace Crypto {
//------------------------------------------------------------------------------
#ifdef ENCLAVED
std::string sealSigner(const std::string &src) {
    std::string ret;
    void *sealed;
    size_t sz;
    if ((sz = seal_signer((const uint8_t *)src.c_str(), src.size(), &sealed)) >
        0) {
        ret = std::string((char *)sealed, sz);
        free(sealed);
    }
    return ret;
}

std::string sealEnclave(const std::string &src) {
    std::string ret;
    void *sealed;
    size_t sz;
    if ((sz = seal_enclave((const uint8_t *)src.c_str(), src.size(), &sealed)) >
        0) {
        ret = std::string((char *)sealed, sz);
        free(sealed);
    }
    return ret;
}

std::string unseal(const std::string &src) {
    std::string ret;
    void *unsealed;
    int len = ::unseal((const uint8_t *)src.c_str(), &unsealed, 0, 0);
    if (len > 0) {
        ret = std::string((const char *)unsealed, len);
        free(unsealed);
    }
    return ret;
}
#endif

//------------------------------------------------------------------------------
#if !defined(ENCLAVED) && !defined(USE_OPENSSL)
void Save(const std::string &filename, const BufferedTransformation &bt) {
    FileSink file(filename.c_str());
    bt.CopyTo(file);
}
//------------------------------------------------------------------------------
void SaveBase64(const std::string &filename, const BufferedTransformation &bt) {
    Base64Encoder encoder;
    bt.CopyTo(encoder);
    encoder.MessageEnd();
    Save(filename, encoder);
}
//------------------------------------------------------------------------------
void Decode(const std::string &filename, BufferedTransformation &bt) {
    FileSource file(filename.c_str(), true /*pumpAll*/);
    file.TransferTo(bt);
    bt.MessageEnd();
}
#endif
//------------------------------------------------------------------------------
void SaveBase64PrivateKey(const std::string &filename, const PrvKey &key) {
#if !defined(ENCLAVED) && !defined(USE_OPENSSL)
    ByteQueue queue;
    key.Save(queue);
    SaveBase64(filename, queue);
#endif
}
//------------------------------------------------------------------------------
void SaveBase64PublicKey(const std::string &filename, const PubKey &key) {
#if !defined(ENCLAVED) && !defined(USE_OPENSSL)
    ByteQueue queue;
    key.Save(queue);
    SaveBase64(filename, queue);
#endif
}
//------------------------------------------------------------------------------
void decodeBase64PrivateKey(const std::string &filename, PrvKey &key) {
#if !defined(ENCLAVED) && !defined(USE_OPENSSL)
    Base64Decoder decoder;
    Decode(filename, decoder);
    decoder.MessageEnd();
    key.Load(decoder);
#endif
}
//------------------------------------------------------------------------------
void decodeBase64PublicKey(const std::string &filename, PubKey &key) {
#if !defined(ENCLAVED) && !defined(USE_OPENSSL)
    Base64Decoder decoder;
    Decode(filename, decoder);
    decoder.MessageEnd();
    key.Load(decoder);
#endif
}
//------------------------------------------------------------------------------
void generateKeysAndSave() {
#if !defined(ENCLAVED) && !defined(USE_OPENSSL)
    CryptoPP::AutoSeededRandomPool rng;

    // Create Keys
    PrvKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 3072);

    PubKey publicKey(privateKey);
    SaveBase64PrivateKey("key.prv", privateKey);
    SaveBase64PublicKey("key.pub", publicKey);
#endif
}

//------------------------------------------------------------------------------
std::string printable(const std::string &s) {
    std::string ret, orep = " [+", crep = "] ";
    bool h = false;
    size_t count = 0;
    char last;
    for (std::string::const_iterator it = s.begin(); it != s.end(); ++it) {
        if (isasciigraph(*it)) {
            if (h) {
                ret += "\033[0m";
                h = false;
            }
            if (count != 0) {
                ret += orep + std::to_string(count) + crep;
                count = 0;
            }
            ret += *it;
        } else {
            if (!h) {
                ret += "\033[38;5;229m";
                h = true;
            }
            // if( !ret.empty() && ret.at(ret.size()-1) == *it ) {
            // printf("%d %d\n", *it, ret[ret.size()-1] );
            if (!ret.empty() && last == *it) {
                ++count;
            } else {
                if (count != 0) {
                    ret += orep + std::to_string(count) + crep;
                    count = 0;
                }
                ret += hexchar(*it);
            }
        }
        last = *it;
    }
    if (count != 0) ret += orep + std::to_string(count) + crep;
    if (h) ret += "\033[0m";
    ;
    return ret;
}

//------------------------------------------------------------------------------
std::string encrypt_rsa(const PubKey &pubkey, const std::string &plain) {
    std::string cipher;
#if !defined(ENCLAVED) && !defined(USE_OPENSSL)
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Encryptor e(pubkey);
    StringSource ss1(
        plain, true,
        new CryptoPP::PK_EncryptorFilter(rng, e, new StringSink(cipher)));
#endif
    return cipher;
}

//------------------------------------------------------------------------------
std::string decrypt_rsa(const PrvKey &prvkey, const std::string &cipher) {
    std::string recovered;
#if !defined(ENCLAVED) && !defined(USE_OPENSSL)
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Decryptor d(prvkey);

    StringSource ss(
        cipher, true,
        new CryptoPP::PK_DecryptorFilter(rng, d, new StringSink(recovered)));
#endif
    return recovered;
}

//------------------------------------------------------------------------------
std::string sha256(const std::string &data) {
    std::string digest;
#if !defined(ENCLAVED) && !defined(USE_OPENSSL)
    CryptoPP::SHA256 hash;
    StringSource foo(
        data, true,
        new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(digest)));
#else
    uint8_t hash[32];
#ifdef ENCLAVED  // intel
    sgx_sha256_msg((const uint8_t *)data.c_str(), data.size(), &hash);
#else            // openssl
    SHA256((const uint8_t *)data.c_str(), data.size(), hash);
#endif
    digest = std::string((char *)hash, 32);
#endif
    return digest;
}

#ifdef ENCLAVED
//------------------------------------------------------------------------------
bool sha256_init(StateSha256 &state) {
    sgx_status_t ret = sgx_sha256_init(&state.context);
    return ret == SGX_SUCCESS;
}

//------------------------------------------------------------------------------
bool sha256_append(StateSha256 &state, const std::string &chunk) {
    sgx_status_t ret = sgx_sha256_update((const uint8_t *)chunk.data(),
                                         chunk.size(), state.context);
    return ret == SGX_SUCCESS;
}

//------------------------------------------------------------------------------
std::string sha256_get(StateSha256 &state) {
    uint8_t hash[32];
    sgx_status_t ret = sgx_sha256_get_hash(state.context, &hash);
    if (ret == SGX_SUCCESS) return std::string((char *)hash, 32);
    return "";
}

#ifdef USE_OPENSSL
#include <openssl/hmac.h>
//------------------------------------------------------------------------------
bool hmac_sha256_init(HMAC_CTX **state, const std::string &key) {
    *state = HMAC_CTX_new();
    return HMAC_Init_ex(*state, key.data(), key.size(), EVP_sha256(), NULL) ==
           1;
}

//------------------------------------------------------------------------------
bool hmac_sha256_append(HMAC_CTX *state, const std::string &data) {
    return HMAC_Update(state, (unsigned char *)data.data(), data.size()) == 1;
}

//------------------------------------------------------------------------------
std::string hmac_sha256_get(HMAC_CTX **state) {
    unsigned char result[32];
    unsigned int len = sizeof(result);
    HMAC_Final(*state, result, &len);
    HMAC_CTX_free(*state);
    *state = 0;
    return std::string((char *)result, len);
}
#endif

#endif

//------------------------------------------------------------------------------
std::string sha224(const std::string &data) {
    std::string digest;
#if !defined(ENCLAVED) && !defined(USE_OPENSSL)
    CryptoPP::SHA224 hash;
    StringSource foo(
        data, true,
        new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(digest)));
#elif defined(USE_OPENSSL)
    uint8_t hash[28];
    SHA224((const uint8_t *)data.data(), data.size(), hash);
    digest = std::string((char *)hash, 28);
#endif
    return digest;
}

//------------------------------------------------------------------------------
std::string hex_encode(const std::string &data) {
    std::string ret;
    std::for_each(data.begin(), data.end(), [&](const char &c) {
        ret += hexchar(c);
    });
    return ret;
}

//------------------------------------------------------------------------------
std::string b64_encode(const std::string &data) {
    std::string ret;
    if (data.empty()) return ret;
#if !defined(ENCLAVED) && !defined(USE_OPENSSL)
    StringSource ssrc(data, true /*pump all*/,
                      new Base64Encoder(new StringSink(ret)));
#elif defined(USE_OPENSSL)
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  // everything in one line
    BIO_write(bio, data.c_str(), data.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    ret = std::string(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
#endif
    return ret;
}

//------------------------------------------------------------------------------
std::string b64_decode(const std::string &data) {
    std::string ret;
#if !defined(ENCLAVED) && !defined(USE_OPENSSL)
    StringSource ssrc(data, true /*pump all*/,
                      new Base64Decoder(new StringSink(ret)));
#elif defined(USE_OPENSSL)
    BIO *b64, *bmem;

    char *buffer = new char[data.size()];
    memset(buffer, 0, data.size());

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(data.c_str(), data.size());
    bmem = BIO_push(b64, bmem);

    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(bmem, BIO_CLOSE);
    size_t outlen = BIO_read(bmem, buffer, data.size());

    ret = std::string(buffer, outlen);
    BIO_free_all(bmem);
    delete[] buffer;
#endif
    return ret;
}

//------------------------------------------------------------------------------
}  // namespace Crypto
