//
// Created by max on 4/30/24.
//

#pragma once

#include <cstdint>
namespace Steam {
    struct SteamID {
        SteamID(std::uint64_t = 0);
        operator std::uint64_t() const;

        union {
            struct {
                unsigned ID : 32;
                unsigned instance : 20;
                unsigned type : 4;
                unsigned universe : 8;
            };
            std::uint64_t steamID64;
        };
    };
}