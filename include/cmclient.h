#include <cryptopp/osrng.h>

#include "steam++.h"
#include "../steam_language/steam_language_internal.h"
#include "steammessages_clientserver.pb.h"
#include "steammessages_clientserver_2.pb.h"

extern const char* MAGIC;
extern std::uint32_t PROTO_MASK;

using namespace CryptoPP;
namespace Steam {
    class CMClient {
    public:
        CMClient(const std::function<void(std::unique_ptr<unsigned char[]> && buffer, const std::size_t len)>& write);

        void WriteMessage(Steam::EMsg emsg, std::unique_ptr<unsigned char[]> && buffer, std::size_t length> &fill);
        void WriteMessage(Steam::EMsg emsg, const google::protobuf::Message& message, std::uint64_t job_id = 0);
        void WritePacket(std::unique_ptr<unsigned char[]> && buffer, std::size_t length);

        const std::function<void(std::unique_ptr<unsigned char[]> buffer, const std::size_t len)> & write;

        SteamID steamID = {};
        std::int32_t sessionID = 0;

        bool encrypted = false;
        byte sessionKey[32] = {};
        AutoSeededRandomPool rnd;
    };

}

