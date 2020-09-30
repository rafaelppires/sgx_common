#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#endif

//------------------------------------------------------------------------------
template<typename T>
std::string Crypto::b64_encode(const T &data) {
    std::string ret;
    if (data.empty()) return ret;
#if defined(USE_OPENSSL)
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  // everything in one line
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    ret = std::string(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
#else
    StringSource ssrc(data, true /*pump all*/,
                      new Base64Encoder(new StringSink(ret)));
#endif
    return ret;
}

//------------------------------------------------------------------------------
template<typename T>
std::string Crypto::b64_decode(const T &data) {
    std::string ret;
#if defined(USE_OPENSSL)
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
#else
    StringSource ssrc(data, true /*pump all*/,
                      new Base64Decoder(new StringSink(ret)));
#endif
    return ret;
}

//------------------------------------------------------------------------------

