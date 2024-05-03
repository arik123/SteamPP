#pragma once
#include <cryptopp/osrng.h>
#include <boost/asio.hpp>

#include "steamid.h"
#include "../steam_language/steam_language_internal.h"
#include "steammessages_clientserver.pb.h"
#include "steammessages_clientserver_2.pb.h"


extern std::uint32_t PROTO_MASK;
namespace Steam {
    constexpr const char* MAGIC = "VT01";

    class CMPacket {
        struct CMPacketHeader {
            std::uint32_t length;
            std::uint32_t magic;
        } * header;
        uint32_t read = 0;
        constexpr static size_t hdrSize = +sizeof(CMPacketHeader);

    public:
        std::vector<unsigned char> body;

        CMPacket(const unsigned char * data, std::size_t data_len);
        /**
         *
         * @return true if whole packet is parsed
         */
        bool addData(const unsigned char * data, std::size_t data_len);

        const boost::asio::mutable_buffer && getBuffer();
    };
    class CMClient {
    public:
        CMClient(std::function<void(std::size_t length, std::function<void(unsigned char* buffer)> fill)> write);

        void WriteMessage(Steam::EMsg emsg, std::size_t length, const std::function<void(unsigned char* buffer)> &fill);
        void WriteMessage(Steam::EMsg emsg, const google::protobuf::Message& message, std::uint64_t job_id = 0);
        void WritePacket(std::size_t length, const std::function<void(unsigned char* buffer)> &fill);

        std::function<void(std::size_t length, std::function<void(unsigned char* buffer)> fill)> write;

        SteamID steamID;
        std::int32_t sessionID;

        bool encrypted;
        CryptoPP::byte sessionKey[32];
        CryptoPP::AutoSeededRandomPool rnd;
    };
}