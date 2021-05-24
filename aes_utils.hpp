#include "crypto_common.h"

namespace Crypto {
//------------------------------------------------------------------------------
template <typename T>
T encrypt_aesgcm(const T &key, const T &plain) {
    unsigned iv_size = 12, tag_size = 16;
    std::string tag, cipher;

    std::vector<uint8_t> cipher_buff(iv_size + tag_size + plain.size());
    ::get_rand_inline(iv_size, cipher_buff.data());  // Creates a rand IV
    encrypt_aes_gcm((const uint8_t *)plain.data(), plain.size(),
                    &cipher_buff[iv_size], &cipher_buff[iv_size + plain.size()],
                    (const uint8_t *)key.data(), cipher_buff.data());
    return cipher_buff;
}

//------------------------------------------------------------------------------
template <typename Key, typename Data>
std::pair<bool, std::vector<uint8_t>> decrypt_aesgcm(const Key &key,
                                                     const Data &cipher) {
    unsigned iv_size = 12, tag_size = 16, meta_size = iv_size + tag_size;
    if (cipher.size() < 1 + meta_size)
        return std::make_pair(false, std::vector<uint8_t>());
    int dec_size = cipher.size() - meta_size;
    std::vector<uint8_t> dec_buff(dec_size);
    std::string plain;
    int ret = decrypt_aes_gcm(
        (const uint8_t *)&cipher[iv_size], dec_size, dec_buff.data(),
        (const uint8_t *)&cipher[iv_size + dec_size],
        (const uint8_t *)key.data(), (const uint8_t *)cipher.data());
    return std::make_pair(ret == 1, dec_buff);
}

//------------------------------------------------------------------------------
}  // namespace Crypto
