//
// Created by Max on 3. 8. 2021.
// REFERENCE https://github.com/DoctorMcKay/node-steam-crypto/blob/master/index.js
//

#include "SteamCrypto.h"
#include "../../consoleColor.h"
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/hmac.h>
#include <cryptopp/modes.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace SteamCrypto {
    CryptoPP::byte public_key[] = {
            0x30, 0x81, 0x9D, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
            0x05, 0x00, 0x03, 0x81, 0x8B, 0x00, 0x30, 0x81, 0x87, 0x02, 0x81, 0x81, 0x00, 0xDF, 0xEC, 0x1A,
            0xD6, 0x2C, 0x10, 0x66, 0x2C, 0x17, 0x35, 0x3A, 0x14, 0xB0, 0x7C, 0x59, 0x11, 0x7F, 0x9D, 0xD3,
            0xD8, 0x2B, 0x7A, 0xE3, 0xE0, 0x15, 0xCD, 0x19, 0x1E, 0x46, 0xE8, 0x7B, 0x87, 0x74, 0xA2, 0x18,
            0x46, 0x31, 0xA9, 0x03, 0x14, 0x79, 0x82, 0x8E, 0xE9, 0x45, 0xA2, 0x49, 0x12, 0xA9, 0x23, 0x68,
            0x73, 0x89, 0xCF, 0x69, 0xA1, 0xB1, 0x61, 0x46, 0xBD, 0xC1, 0xBE, 0xBF, 0xD6, 0x01, 0x1B, 0xD8,
            0x81, 0xD4, 0xDC, 0x90, 0xFB, 0xFE, 0x4F, 0x52, 0x73, 0x66, 0xCB, 0x95, 0x70, 0xD7, 0xC5, 0x8E,
            0xBA, 0x1C, 0x7A, 0x33, 0x75, 0xA1, 0x62, 0x34, 0x46, 0xBB, 0x60, 0xB7, 0x80, 0x68, 0xFA, 0x13,
            0xA7, 0x7A, 0x8A, 0x37, 0x4B, 0x9E, 0xC6, 0xF4, 0x5D, 0x5F, 0x3A, 0x99, 0xF9, 0x9E, 0xC4, 0x3A,
            0xE9, 0x63, 0xA2, 0xBB, 0x88, 0x19, 0x28, 0xE0, 0xE7, 0x14, 0xC0, 0x42, 0x89, 0x02, 0x01, 0x11,
    };
}


SteamCrypto::sessionKey SteamCrypto::generateSessionKey(const std::vector<uint8_t>& nonce) { //THIS SHOULD NOT BE THE PROBLEM

    //   Using a ANSI approved Cipher
    CryptoPP::AutoSeededRandomPool rng;

    sessionKey sessKey;
    sessKey.plain.resize(32);
    rng.GenerateBlock( sessKey.plain.data(), 32 );
/*
    CryptoPP::RSA::PublicKey pk;
    CryptoPP::ArraySource source(public_key, sizeof(public_key), true);
    pk.Load(source);
    bool valid = pk.Validate(rng, 3);
    CryptoPP::RSAES_OAEP_SHA_Encryptor rsa(pk);
    std::vector<uint8_t> toEncrypt = key.plain;
    toEncrypt.insert(toEncrypt.end(), nonce.begin(), nonce.end());
    key.encrypted.resize(rsa.CiphertextLength(toEncrypt.size()));
    rsa.Encrypt(rng, toEncrypt.data(), toEncrypt.size(), key.encrypted.data());*/
    const char * pem = "-----BEGIN PUBLIC KEY-----\n"
                      "MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDf7BrWLBBmLBc1OhSwfFkRf53T\n"
                      "2Ct64+AVzRkeRuh7h3SiGEYxqQMUeYKO6UWiSRKpI2hzic9pobFhRr3Bvr/WARvY\n"
                      "gdTckPv+T1JzZsuVcNfFjrocejN1oWI0Rrtgt4Bo+hOneoo3S57G9F1fOpn5nsQ6\n"
                      "6WOiu4gZKODnFMBCiQIBEQ==\n"
                      "-----END PUBLIC KEY-----";
    EVP_PKEY *key = nullptr;
    BIO* in = BIO_new_mem_buf(pem, strlen(pem));
    key = PEM_read_bio_PUBKEY(in, nullptr,nullptr, nullptr);
    BIO_free(in);

    size_t out_len = 0;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, nullptr);

    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_encrypt(ctx, nullptr, &out_len, (unsigned char *) sessKey.plain.data(), sessKey.plain.size()) <= 0) {
        std::cout << "ERROR with encryption" << std::endl;
    }

    sessKey.encrypted.resize(out_len);
    if (EVP_PKEY_encrypt(ctx, sessKey.encrypted.data(), &out_len,
                         (unsigned char *) sessKey.plain.data(), sessKey.plain.size()) <= 0) {
        std::cout << "ERROR with encryption" << std::endl;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    return sessKey;
}

std::vector<uint8_t> SteamCrypto::symmetricEncryptWithHmacIv(std::vector<uint8_t> input, std::vector<uint8_t> key) {
    CryptoPP::AutoSeededRandomPool rng;
    std::vector<uint8_t> random(3);
    rng.GenerateBlock( random.data(), 3 );

    std::vector<uint8_t> keySlice(key.begin(), key.begin()+std::min(key.size(), (size_t)16));
    CryptoPP::HMAC<CryptoPP::SHA1> hmac(keySlice.data(), keySlice.size());

    hmac.Update(random.data(), random.size());
    hmac.Update(input.data(), input.size());

    std::vector<uint8_t> digest(CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE);
    hmac.Final(digest.data());
    digest.resize(16 - random.size());
    digest.insert(digest.end(), random.begin(), random.end());

    return symmetricEncrypt(input, key, digest);
}

std::vector<uint8_t> SteamCrypto::symmetricEncrypt(std::vector<uint8_t> input, std::vector<uint8_t> key, std::vector<uint8_t> iv) {
    if(key.size() != 32) {
        std::cout << color(colorFG::Bright_Red) << "SymmetricEncrypt used with non 32 byte key!" << color();
    }
    CryptoPP::AutoSeededRandomPool rng;
    if(iv.empty()) {
        iv.resize(16);
        rng.GenerateBlock( iv.data(), 16 );
    }
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption ecb_e;
    ecb_e.SetKey(key.data(), key.size());
    auto ivc = iv; //copy iv
    ecb_e.ProcessString(ivc.data(), ivc.size());

    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cbc_e;
    std::vector<uint8_t> out;
    // Make room for padding
    out.resize(input.size() + (CryptoPP::AES::BLOCKSIZE - (input.size() % CryptoPP::AES::BLOCKSIZE) ) );
    cbc_e.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    CryptoPP::ArraySource(
                input.data(),
                input.size(),
                true,
                new CryptoPP::StreamTransformationFilter(cbc_e,
                    new CryptoPP::ArraySink(out.data(), out.size())
                )
            );

    std::vector<uint8_t> output = ivc;
    output.insert(output.end(), out.begin(), out.end());

    return output;
}