#include <cryptopp/modes.h>

#include "../include/cmclient.h"

const char* MAGIC = "VT01";
std::uint32_t PROTO_MASK = 0x80000000;
using namespace Steam;
CMClient::CMClient(const std::function<void(std::unique_ptr<unsigned char[]> && buffer, const std::size_t len)>& write) : write(write) {
	steamID.instance = 1;
	steamID.universe = static_cast<unsigned>(EUniverse::Public);
	steamID.type = static_cast<unsigned>(EAccountType::Individual);
}

void CMClient::WriteMessage(EMsg emsg, std::unique_ptr<unsigned char[]> && buffer, std::size_t length) {
    std::unique_ptr<unsigned char[]> buff;
    std::size_t offset;
	if (emsg == EMsg::ChannelEncryptResponse) {
        offset =  sizeof(MsgHdr);
        buff = std::make_unique<unsigned char[]>(offset + length);

        auto header = reinterpret_cast<MsgHdr*>(buff.get());
        header->msg = static_cast<std::uint32_t>(emsg);
	} else {
        offset =  sizeof(ExtendedClientMsgHdr);
        buff = std::make_unique<unsigned char[]>(offset + length);

        auto header = reinterpret_cast<ExtendedClientMsgHdr*>(buff.get());
        header->msg = static_cast<std::uint32_t>(emsg);
        header->sessionID = sessionID;
        header->steamID = steamID;
	}
    std::memcpy(buff.get() + offset, buffer.get(), length);

    WritePacket(std::move(buff), offset + length);
}

void CMClient::WriteMessage(EMsg emsg, const google::protobuf::Message &message, std::uint64_t job_id) {
#ifdef _DEBUG
	std::cout << "Sending: " << message.GetTypeName() << '\n';
#endif
	CMsgProtoBufHeader proto;
	proto.set_steamid(steamID);
	proto.set_client_sessionid(sessionID);
	if (job_id) {
		proto.set_jobid_target(job_id);
	}
	auto proto_size = proto.ByteSizeLong();
	auto message_size = message.ByteSizeLong();

    const std::size_t totalSize = sizeof(MsgHdrProtoBuf) + proto_size + message_size;
    auto buff = std::make_unique<unsigned char[]>(totalSize);

    auto header = reinterpret_cast<MsgHdrProtoBuf*>(buff.get());
    header->headerLength = proto_size;
    header->msg = static_cast<std::uint32_t>(emsg) | PROTO_MASK;
    proto.SerializeToArray(header->proto, proto_size);
    message.SerializeToArray(header->proto + proto_size, message_size);
    WritePacket(std::move(buff), totalSize);
}

void CMClient::WritePacket(std::unique_ptr<unsigned char[]> && buffer, const std::size_t length) {
	if (encrypted) {
		auto crypted_size = 16 + (length / 16 + 1) * 16; // IV + crypted message padded to multiple of 16
		
		write(8 + crypted_size, [&](unsigned char* out_buffer) {
			auto in_buffer = new unsigned char[length];
			fill(in_buffer);
			
			byte iv[16];
			rnd.GenerateBlock(iv, 16);
			
			auto crypted_iv = out_buffer + 8;
			ECB_Mode<AES>::Encryption(sessionKey, sizeof(sessionKey)).ProcessData(crypted_iv, iv, sizeof(iv));
			
			auto crypted_data = crypted_iv + 16;
			CBC_Mode<AES>::Encryption e(sessionKey, sizeof(sessionKey), iv);
			ArraySource(
				in_buffer,
				length,
				true,
				new StreamTransformationFilter(e, new ArraySink(crypted_data, crypted_size - 16))
			);
			
			*reinterpret_cast<std::uint32_t*>(out_buffer) = crypted_size;
			std::copy(MAGIC, MAGIC + 4, out_buffer + 4);
			
			delete[] in_buffer;
		});
	} else {
        auto buff = std::make_unique<unsigned char[]>(8 + length);
        *reinterpret_cast<std::uint32_t*>(buff.get()) = length;
        std::copy(MAGIC, MAGIC + 4, buff.get() + 4);

        //TODO: decide for fill - prevent copy

		write(8 + length, [&](unsigned char* buffer) {
			*reinterpret_cast<std::uint32_t*>(buffer) = length;
			std::copy(MAGIC, MAGIC + 4, buffer + 4);
			fill(buffer + 8);
		});
	}
}
