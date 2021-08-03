//
// Created by Max on 3. 8. 2021.
//
#pragma once
#ifndef STEAMBOT_STEAMCRYPTO_H
#define STEAMBOT_STEAMCRYPTO_H
#include <vector>
#include <string>

namespace SteamCrypto {
    struct sessionKey {
        std::vector<uint8_t> plain;
        std::vector<uint8_t> encrypted;
    };
    sessionKey generateSessionKey(const std::vector<uint8_t>& nonce = {});
    std::vector<uint8_t> symmetricEncryptWithHmacIv(std::vector<uint8_t> input, std::vector<uint8_t> key);
    std::vector<uint8_t> symmetricEncrypt(std::vector<uint8_t> input, std::vector<uint8_t> key, std::vector<uint8_t> iv);

};
#endif //STEAMBOT_STEAMCRYPTO_H
