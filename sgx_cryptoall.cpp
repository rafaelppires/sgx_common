#include "sgx_cryptoall.h"

#ifndef ENABLE_SGX
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
