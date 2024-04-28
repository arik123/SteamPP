#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iomanip>

#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <steammessages_clientserver_login.pb.h>
#include <steammessages_clientserver_friends.pb.h>

#include "cmclient.h"
#include "steam++.h"
#include "SteamCrypto.h"
#include "../../SteamApi.h"
#include "../../consoleColor.h"
#include <boost/beast/core/detail/base64.hpp>


SteamID::SteamID(std::uint64_t steamID64) :
	steamID64(steamID64) {}

SteamID::operator std::uint64_t() const {
	return steamID64;
}

SteamClient::SteamClient(
	std::function<void(std::size_t length, std::function<void(unsigned char* buffer)> fill)> write,
	std::function<void(std::function<void()> callback, int timeout)> set_interval
) : cmClient(new CMClient(std::move(write))), setInterval(std::move(set_interval)) {}

SteamClient::~SteamClient() {
	delete cmClient;
}

void SteamClient::LogOn(const char* username, const char* password, const unsigned char hash[20], const char* code, SteamID steamID) {
    //FIXME: OUTDATED
	if (steamID)
		cmClient->steamID = steamID;

	CMsgClientLogon logon;
	logon.set_account_name(username);
	logon.set_password(password);
	logon.set_protocol_version(65580);
	if (hash) {
		logon.set_sha_sentryfile(hash, 20);
	}
	if (code) {
		logon.set_auth_code(code);
		logon.set_two_factor_code(code);
	}
	cmClient->WriteMessage(EMsg::ClientLogon, logon);
}

void SteamClient::SetPersonaState(EPersonaState state) {
	CMsgClientChangeStatus change_status;
	change_status.set_persona_state(static_cast<google::protobuf::uint32>(state));
	cmClient->WriteMessage(EMsg::ClientChangeStatus, change_status);
}

void SteamClient::SetPersona(EPersonaState state, const char * name) {
    CMsgClientChangeStatus change_status;
    change_status.set_persona_state(static_cast<google::protobuf::uint32>(state));
    change_status.set_player_name(name);
    cmClient->WriteMessage(EMsg::ClientChangeStatus, change_status);
}

void SteamClient::SetGamePlayed(int gameID) {
	CMsgClientGamesPlayed changedStatus;
	changedStatus.add_games_played();
	changedStatus.mutable_games_played(0)->set_game_id(gameID);
    cmClient->WriteMessage(EMsg::ClientGamesPlayed, changedStatus);
}
void SteamClient::SetGamePlayed(std::string name) {
    CMsgClientGamesPlayed changedStatus;
	changedStatus.add_games_played();
	changedStatus.mutable_games_played(0)->set_game_id(15190414816125648896u);
	changedStatus.mutable_games_played(0)->set_game_extra_info(name);
    cmClient->WriteMessage(EMsg::ClientGamesPlayed, changedStatus);
}
#pragma region groupChat
void SteamClient::JoinChat(SteamID chat) {
	if (chat.type == static_cast<unsigned>(EAccountType::Clan)) {
		// this is a ClanID - convert to its respective ChatID
		chat.instance = static_cast<unsigned>(0x100000 >> 1); // TODO: this should be defined somewhere else
		chat.type = static_cast<unsigned>(EAccountType::Chat);
	}

	cmClient->WriteMessage(EMsg::ClientJoinChat, sizeof(MsgClientJoinChat), [&chat](unsigned char* buffer) {
		auto join_chat = new (buffer) MsgClientJoinChat;
		join_chat->steamIdChat = chat;
	});
}

void SteamClient::LeaveChat(SteamID chat) {
	// TODO: move this somwehre else
	if (chat.type == static_cast<unsigned>(EAccountType::Clan)) {
		// this is a ClanID - convert to its respective ChatID
		chat.instance = static_cast<unsigned>(0x100000 >> 1); // TODO: this should be defined somewhere else
		chat.type = static_cast<unsigned>(EAccountType::Chat);
	}

	cmClient->WriteMessage(EMsg::ClientChatMemberInfo, sizeof(MsgClientChatMemberInfo) + 20, [&](unsigned char* buffer) {
		auto leave_chat = new (buffer) MsgClientChatMemberInfo;
		leave_chat->steamIdChat = chat;
		leave_chat->type = static_cast<unsigned>(EChatInfoType::StateChange);

		auto payload = buffer + sizeof(MsgClientChatMemberInfo);
		*reinterpret_cast<std::uint64_t*>(payload) = cmClient->steamID; // chatter_acted_on
		*reinterpret_cast<EChatMemberStateChange*>(payload + 8) = EChatMemberStateChange::Left; // state_change
		*reinterpret_cast<std::uint64_t*>(payload + 8 + 4) = cmClient->steamID; // chatter_acted_by
	});
}

void SteamClient::SendChatMessage(SteamID chat, const char* message) {
	// TODO: move this somwehre else
	if (chat.type == static_cast<unsigned>(EAccountType::Clan))	{
		// this is a ClanID - convert to its respective ChatID
		chat.instance = static_cast<unsigned>(0x100000 >> 1); // TODO: this should be defined somewhere else
		chat.type = static_cast<unsigned>(EAccountType::Chat);
	}

	cmClient->WriteMessage(EMsg::ClientChatMsg, sizeof(MsgClientChatMsg) + std::strlen(message) + 1, [&](unsigned char* buffer) {
		auto send_msg = new (buffer) MsgClientChatMsg;
		send_msg->chatMsgType = static_cast<std::uint32_t>(EChatEntryType::ChatMsg);
		send_msg->steamIdChatRoom = chat;
		send_msg->steamIdChatter = cmClient->steamID;

		std::strcpy(reinterpret_cast<char*>(buffer + sizeof(MsgClientChatMsg)), message);
	});
}
#pragma endregion groupChat
void SteamClient::SendPrivateMessage(SteamID user, const char* message) {
	CMsgClientFriendMsg msg;

	msg.set_steamid(user);
	msg.set_message(message);
	msg.set_chat_entry_type(static_cast<google::protobuf::uint32>(EChatEntryType::ChatMsg));

	cmClient->WriteMessage(EMsg::ClientFriendMsg, msg);
}

void SteamClient::SendTyping(SteamID user) {
	CMsgClientFriendMsg msg;

	msg.set_steamid(user);
	msg.set_chat_entry_type(static_cast<google::protobuf::uint32>(EChatEntryType::Typing));

	cmClient->WriteMessage(EMsg::ClientFriendMsg, msg);
}

void SteamClient::RequestUserInfo(std::size_t count, SteamID users[]) {
	CMsgClientRequestFriendData request;

	while (count--)
		request.add_friends(users[count]);

	// TODO: allow custom flags
	request.set_persona_state_requested(282);

	cmClient->WriteMessage(EMsg::ClientRequestFriendData, request);
}
template <typename T>
void Steam::SteamClient::SendCMsg(T& Proto, EMsg eMsg)
{
	cmClient->WriteMessage(eMsg, Proto);
}

std::size_t SteamClient::connected() {
	packetLength = 0;
	cmClient->steamID.ID = 0;
	cmClient->sessionID = 0;
	cmClient->encrypted = false;

	return 8;
}

std::size_t SteamClient::readable(const unsigned char* input) {
	if (!packetLength) {
		packetLength = *reinterpret_cast<const std::uint32_t*>(input);
		assert(std::equal(MAGIC, MAGIC + 4, input + 4));
		return packetLength;
	}

	if (cmClient->encrypted) {
		byte iv[16];
		ECB_Mode<AES>::Decryption(cmClient->sessionKey, sizeof(cmClient->sessionKey)).ProcessData(iv, input, 16);

		auto crypted_data = input + 16;
		CBC_Mode<AES>::Decryption d(cmClient->sessionKey, sizeof(cmClient->sessionKey), iv);
		// I don't see any way to get the decrypted size other than to use a string
		std::string output;
		try {
            ArraySource(
                    crypted_data,
                    packetLength - 16,
                    true,
                    new StreamTransformationFilter(d, new StringSink(output))
            );
        } catch (std::exception &e) {
		    std::cout << e.what() << '\n';
		}
		ReadMessage(reinterpret_cast<const unsigned char*>(output.data()), output.length());
	} else {
		ReadMessage(input, packetLength);
	}

	packetLength = 0;
	return 8;
}

void SteamClient::ReadMessage(const unsigned char* data, std::size_t length) {
	auto raw_emsg = *reinterpret_cast<const std::uint32_t*>(data);
	auto emsg = static_cast<EMsg>(raw_emsg & ~PROTO_MASK);

	// first figure out the header type
	if (emsg == EMsg::ChannelEncryptRequest || emsg == EMsg::ChannelEncryptResult) {
		auto header = reinterpret_cast<const MsgHdr*>(data);
		HandleMessage(emsg, data + sizeof(MsgHdr), length - sizeof(MsgHdr), header->sourceJobID);
	} else if (raw_emsg & PROTO_MASK) {
		auto header = reinterpret_cast<const MsgHdrProtoBuf*>(data);
		CMsgProtoBufHeader proto;
		proto.ParseFromArray(header->proto, header->headerLength);
		if (!cmClient->sessionID && header->headerLength > 0) {
			cmClient->sessionID = proto.client_sessionid();
			cmClient->steamID = proto.steamid();
		}
		HandleMessage(
			emsg,
			data + sizeof(MsgHdrProtoBuf) + header->headerLength,
			length - sizeof(MsgHdrProtoBuf) - header->headerLength,
			proto.jobid_source()
		);
	} else {
		auto header = reinterpret_cast<const ExtendedClientMsgHdr*>(data);
		HandleMessage(emsg, data + sizeof(ExtendedClientMsgHdr), length - sizeof(ExtendedClientMsgHdr), header->sourceJobID);
	}
}

void Steam::SteamClient::webLogOn() {
    CMsgClientRequestWebAPIAuthenticateUserNonce request;
    cmClient->WriteMessage(EMsg::ClientRequestWebAPIAuthenticateUserNonce, request);
}
void Steam::SteamClient::_webAuthenticate (const std::string& nonce) {
    // https://github.com/Jessecar96/SteamBot/blob/master/SteamTrade/SteamWeb.cs#L395
    https://github.com/Jessecar96/SteamBot/blob/master/SteamTrade/SteamWeb.cs#L333
    // https://github.com/DoctorMcKay/node-steam-user/blob/master/components/web.js#L30
    if(api == nullptr) throw "No steam api";
    // Encrypt the nonce. I don't know if the client uses HMAC IV here, but there's no harm in it...
    auto sessionKey = SteamCrypto::generateSessionKey();
    auto encryptedNonce = SteamCrypto::symmetricEncryptWithHmacIv(std::vector<uint8_t> (nonce.begin(), nonce.end()), sessionKey.plain); //TODO CHECK WITH STEAM-CRYPTO
    std::string SessionID;
    SessionID.resize(boost::beast::detail::base64::encoded_size(myUniqueId.size()));
    boost::beast::detail::base64::encode(SessionID.data(), myUniqueId.c_str(), myUniqueId.size());
    std::cout << SessionID << std::endl;

    api->request("ISteamUserAuth", "AuthenticateUser", "v0001", true, {
            { "steamid", std::to_string(cmClient->steamID.steamID64) },
            { "sessionkey", sessionKey.encrypted},
            { "encrypted_loginkey", encryptedNonce},
            {"format", "json"}
        },
        [&, SessionID](http::response<http::string_body>& resp){
            std::vector<std::string> cookies;
            if(resp.result_int() == 200){
                cookies.emplace_back("sessionid=" + SessionID);
                if (resp[http::field::content_type].starts_with("application/json")) {
                    rapidjson::Document document;
                    document.ParseInsitu(resp.body().data());

                    if(document.HasMember("authenticateuser") && document["authenticateuser"].HasMember("token")){
                        std::string token = document["authenticateuser"]["token"].GetString();
                        cookies.emplace_back("steamLogin=" + token);
                    }

                    if(document.HasMember("authenticateuser") && document["authenticateuser"].HasMember("tokensecure")){
                        std::string tokensecure = document["authenticateuser"]["token"].GetString();
                        cookies.emplace_back("steamLoginSecure=" + std::to_string(cmClient->steamID.steamID64) + "%7C%7C" + tokensecure);
                    }
                }
                cookies.emplace_back("Steam_Language=english");
                cookies.emplace_back("timezoneOffset=0,0");
                //onWebSession(cookies, (std::string)SessionID);
            }
        });
/*
    try {
        /let res = await this._apiRequest('POST', 'ISteamUserAuth', 'AuthenticateUser', 1, data);
        / (!res.authenticateuser || (!res.authenticateuser.token && !res.authenticateuser.tokensecure)) {
        /    throw new Error('Malformed response');
        /}

        // Generate a random sessionid (CSRF token)
        /let sessionid = Crypto.randomBytes(12).toString('hex');
        let cookies = ['sessionid=' + sessionid];
        if (res.authenticateuser.token) {
            cookies.push('steamLogin=' + res.authenticateuser.token);
        }
        if (res.authenticateuser.tokensecure) {
            cookies.push('steamLoginSecure=' + res.authenticateuser.tokensecure);
        }

        this.emit('webSession', sessionid, cookies);
    } catch (ex) {
        this.emit('debug', 'Webauth failed: ' + ex.message);

        if (ex.message == 'HTTP error 429') {
            // We got rate-limited
            this._webauthTimeout = 50000;
        }

        if (this._webauthTimeout) {
            this._webauthTimeout = Math.min(this._webauthTimeout * 2, 50000);
        } else {
            this._webauthTimeout = 1000;
        }

        setTimeout(this._webLogOn.bind(this), this._webauthTimeout);
    }
    */
}