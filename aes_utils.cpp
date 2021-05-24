#include <aes_utils.h>
#include <crypto_common.h>
#include <string.h>
#include <iostream>
#ifdef USE_OPENSSL  // openssl {
#include <openssl/evp.h>
#elif defined(ENCLAVED)  // } else if sgx {
// maybe ipp stuff
#else                    // no openssl nor enclave, so crypto++
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
using CryptoPP::AES;
using CryptoPP::byte;
using CryptoPP::CTR_Mode;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
#endif

#if defined(__cplusplus)
namespace Crypto {
//------------------------------------------------------------------------------
void encrypt_aes_inline(const std::string &key, std::string &plain) {
    plain = encrypt_aes(key, plain);
}

//------------------------------------------------------------------------------
void decrypt_aes_inline(const std::string &key, std::string &cipher) {
    cipher = decrypt_aes(key, cipher);
}

//------------------------------------------------------------------------------
std::string encrypt_aes(const std::string &k, const std::string &plain) {
    std::string cipher;
    unsigned char key[32];
    memset(key, 0, sizeof(key));
    memcpy(key, k.c_str(), std::min(sizeof(key), k.size()));

    // Creates a rand IV
    auto iv = get_rand(16);
#if !defined(ENCLAVED) && !defined(USE_OPENSSL)
    try {
        CTR_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, k.size() > 16 ? 32 : 16, (const byte *)iv.data());

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(plain, true,
                     new StreamTransformationFilter(e, new StringSink(cipher)));
    } catch (const CryptoPP::Exception &e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
#else
    uint8_t *buff = new uint8_t[plain.size()];
    int ret = ::encrypt_aes(k.size() > 16 ? AES256 : AES128,
                            (const uint8_t *)plain.c_str(), buff, plain.size(),
                            key, (uint8_t *)iv.data());
    if (ret == plain.size()) cipher = std::string((char *)buff, ret);
    delete[] buff;
#endif

    // First 16 bytes corresponds to the generated IV
    return std::string(iv.begin(), iv.end()) + cipher;
}

//------------------------------------------------------------------------------
std::string decrypt_aes(const std::string &k, const std::string &cipher) {
    std::string plain;
    unsigned char key[32], iv[16];
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    memcpy(key, k.c_str(), std::min(k.size(), sizeof(key)));
    memcpy(iv, cipher.c_str(), std::min(cipher.size(), sizeof(iv)));

    if (cipher.size() > 16) {
#if !defined(ENCLAVED) && !defined(USE_OPENSSL)
        try {
            CTR_Mode<AES>::Decryption d;
            d.SetKeyWithIV(key, k.size() > 16 ? 32 : 16, iv);

            // The StreamTransformationFilter adds padding
            //  as required. ECB and CBC Mode must be padded
            //  to the block size of the cipher.
            StringSource(
                cipher.substr(sizeof(iv)), true,
                new StreamTransformationFilter(d, new StringSink(plain)));
        } catch (const CryptoPP::Exception &e) {
            std::cerr << e.what() << std::endl;
            exit(1);
        }
#else
        size_t sz = cipher.size() - 16;
        uint8_t *buff = new uint8_t[sz];
        int ret = ::decrypt_aes(k.size() > 16 ? AES256 : AES128,
                                (const uint8_t *)cipher.c_str() + 16, buff, sz,
                                key, iv);
        if (ret == sz) plain = std::string((char *)buff, sz);
        delete[] buff;
#endif
    }
    return plain;
}

//------------------------------------------------------------------------------
}  // namespace Crypto
#endif  // __cplusplus

//------------------------------------------------------------------------------
int encrypt_aes(char type, const uint8_t *plain, uint8_t *cipher, size_t plen,
                const uint8_t *key, uint8_t *iv) {
    int ret = 0;
#ifdef USE_OPENSSL  //     openssl {
    int len;
    int cipher_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *ciph =
        type == AES128 ? EVP_aes_128_ctr() : EVP_aes_256_ctr();
    if (type != AES128 && type != AES256) {
        ret = -1;
        goto getout;
    }
    ret |= !EVP_EncryptInit_ex(ctx, ciph, NULL, key, iv);
    ret |= !EVP_EncryptUpdate(ctx, cipher, &len, plain, plen);
    cipher_len = len;
    ret |= !EVP_EncryptFinal_ex(ctx, cipher + len, &len);
    cipher_len += len;
getout:
    EVP_CIPHER_CTX_free(ctx);
    if (ret != -1) ret = ret ? -2 : cipher_len;
#elif defined(ENCLAVED)  //     } openssl else intel sdk {
    uint8_t i[16];
    memcpy(i, iv,
           16);  // intel's aes updates iv assuming `src` is a stream chunk
    if (type != AES128)  // not supported by intel sdk
        ret = -1;
    else if (SGX_SUCCESS == sgx_aes_ctr_encrypt((uint8_t(*)[16])key, plain,
                                                plen, i, 128, cipher))
        ret = plen;
    else
        ret = -2;
#else                    //     } intel sdk else crypto++ {
    try {
        size_t ksz = type == AES128 ? 16 : (type == AES256 ? 32 : 0);
        CTR_Mode<AES>::Encryption e;
        std::string cphr, pl((const char *)plain, plen);
        if (!ksz) {
            ret = -1;
            goto getout;
        }
        e.SetKeyWithIV(key, ksz, iv);
        StringSource(pl, true,
                     new StreamTransformationFilter(e, new StringSink(cphr)));
        memcpy(cipher, cphr.c_str(), ret = std::min(plen, cphr.size()));
    } catch (const CryptoPP::Exception &e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

getout:
#endif                   //     } crypto++
    return ret;
}

//------------------------------------------------------------------------------
int decrypt_aes(char type, const uint8_t *cipher, uint8_t *plain, size_t clen,
                const uint8_t *key, uint8_t *iv) {
    int ret = 0;
#ifdef USE_OPENSSL  //     openssl {
    EVP_CIPHER_CTX *ctx;
    int len;
    ctx = EVP_CIPHER_CTX_new();
    if (type == AES128)
        EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    else if (type == AES256)
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
#elif defined(ENCLAVED)  //     } openssl else intel sdk {
    if (type != AES128)  // not supported by intel sdk
        ret = -1;
    else if (SGX_SUCCESS == sgx_aes_ctr_decrypt((uint8_t(*)[16])key, cipher,
                                                clen, iv, 128, plain))
        ret = clen;
    else
        ret = -2;
#else                    //     } intel sdk else crypto++ {
    size_t ksz = type == AES128 ? 16 : (type == AES256 ? 32 : 0);
    CTR_Mode<AES>::Decryption d;
    std::string recov, ciph((const char *)cipher, clen);
    if (!ksz) {
        ret = -1;
        goto getout;
    }
    d.SetKeyWithIV(key, ksz, iv);
    StringSource(ciph, true,
                 new StreamTransformationFilter(d, new StringSink(recov)));
    memcpy(plain, recov.c_str(), ret = std::min(clen, recov.size()));
getout:
#endif                   //     } crypto++
    return ret;
}

//------------------------------------------------------------------------------
void encrypt_aes_gcm(const uint8_t *plain, int in_len, uint8_t *ciphertext,
                     uint8_t *tag, const uint8_t *key, const uint8_t *iv) {
#ifdef USE_OPENSSL
    int howmany, dec_success, len;  //, aad_len = 0;
    // const uint8_t *AAD = NULL;
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    // Encrypt
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, cipher, key, iv);
    // EVP_EncryptUpdate (ctx, NULL, &howmany, AAD, aad_len);
    len = 0;
    while (len <= in_len - 128) {
        EVP_EncryptUpdate(ctx, ciphertext + len, &howmany, plain + len, 128);
        len += 128;
    }
    EVP_EncryptUpdate(ctx, ciphertext + len, &howmany, plain + len,
                      in_len - len);
    EVP_EncryptFinal(ctx, tag, &howmany);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
#elif ENCLAVED
    sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *)key, plain,
                               in_len, ciphertext, iv, 12, nullptr, 0,
                               (sgx_aes_gcm_128bit_tag_t *)tag);
#endif
}

//------------------------------------------------------------------------------
int decrypt_aes_gcm(const uint8_t *ciphertext, int in_len, uint8_t *decrypted,
                    const uint8_t *tag, const uint8_t *key, const uint8_t *iv) {
#ifdef USE_OPENSSL
    int howmany, dec_success, len, tag_size=16;  
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    // Decrypt
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, cipher, key, iv);
    uint8_t reftag[tag_size];
    memcpy(reftag, tag, tag_size);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_size, reftag);
    EVP_DecryptInit(ctx, NULL, key, iv);
    // EVP_DecryptUpdate (ctx, NULL, &howmany, AAD, aad_len);
    len = 0;
    while (len <= in_len - 128) {
        EVP_DecryptUpdate(ctx, decrypted + len, &howmany, ciphertext + len,
                          128);
        len += 128;
    }
    EVP_DecryptUpdate(ctx, decrypted + len, &howmany, ciphertext + len,
                      in_len - len);
    uint8_t dec_TAG[tag_size];
    dec_success = EVP_DecryptFinal(ctx, dec_TAG, &howmany);
    EVP_CIPHER_CTX_free(ctx);
    return dec_success;
#elif ENCLAVED
    sgx_status_t status = sgx_rijndael128GCM_decrypt(
        (const sgx_aes_gcm_128bit_key_t *)key, ciphertext, in_len, decrypted,
        iv, 12, nullptr, 0, (const sgx_aes_gcm_128bit_tag_t *)reftag);
    return status == SGX_SUCCESS ? 1 : 0;
#endif
}

//------------------------------------------------------------------------------
