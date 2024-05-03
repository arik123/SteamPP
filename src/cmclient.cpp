#include <cryptopp/modes.h>

#include "../include/cmclient.h"

std::uint32_t PROTO_MASK = 0x80000000;
using namespace Steam;
using namespace CryptoPP;

CMClient::CMClient(std::function<void(std::size_t, std::function<void(unsigned char*)>)> write) : write(std::move(write)) {
	steamID.instance = 1;
	steamID.universe = static_cast<unsigned>(EUniverse::Public);
	steamID.type = static_cast<unsigned>(EAccountType::Individual);
}

void CMClient::WriteMessage(EMsg emsg, std::size_t length, const std::function<void(unsigned char*)> &fill) {
	if (emsg == EMsg::ChannelEncryptResponse) {
		WritePacket(sizeof(MsgHdr) + length, [emsg, &fill](unsigned char* buffer) {
			auto header = new (buffer) MsgHdr;
			header->msg = static_cast<std::uint32_t>(emsg);
			fill(buffer + sizeof(MsgHdr));
		});
	} else {
		WritePacket(sizeof(ExtendedClientMsgHdr) + length, [this, emsg, &fill](unsigned char* buffer) {
			auto header = new (buffer) ExtendedClientMsgHdr;
			header->msg = static_cast<std::uint32_t>(emsg);
			header->sessionID = sessionID;
			header->steamID = steamID;
			fill(buffer + sizeof(ExtendedClientMsgHdr));
		});
	}
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
	WritePacket(sizeof(MsgHdrProtoBuf) + proto_size + message_size, [emsg, &proto, proto_size, &message, message_size](unsigned char* buffer) {
		auto header = new (buffer) MsgHdrProtoBuf;
		header->headerLength = proto_size;
		header->msg = static_cast<std::uint32_t>(emsg) | PROTO_MASK;
		proto.SerializeToArray(header->proto, proto_size);
		message.SerializeToArray(header->proto + proto_size, message_size);
	});
}


void CMClient::WritePacket(const std::size_t length, const std::function<void(unsigned char* buffer)> &fill) {
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
		write(8 + length, [&](unsigned char* buffer) {
			*reinterpret_cast<std::uint32_t*>(buffer) = length;
			std::copy(MAGIC, MAGIC + 4, buffer + 4);
			fill(buffer + 8);
		});
	}
}

CMPacket::CMPacket(const unsigned char *data, std::size_t data_len) {
    if(data_len < hdrSize) throw std::runtime_error("invalid header");
    const auto hdr = reinterpret_cast<const CMPacketHeader*>(data);
    if(memcmp(&hdr->magic,  MAGIC, std::strlen(MAGIC)) != 0) throw std::runtime_error("invalid packet magic");
    body.resize(hdr->length - hdrSize);
    std::memcpy(body.data(), data, std::min((uint32_t)data_len, hdr->length));

}

bool CMPacket::addData(const unsigned char *data, std::size_t data_len) {
    return false;
}

const boost::asio::mutable_buffer && CMPacket::getBuffer() {
    return boost::asio::mutable_buffer();
}
