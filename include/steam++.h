#pragma once

#include <functional>
#include <map>
#include <string>
#include <array>
#include <queue>
#include <semaphore>

#include "../steam_language/steam_language.h"
#include "SteamApi.h"
#include "../include/utils.h"
#include "steamid.h"
#include "cmclient.h"

namespace Steam {
#pragma pack(push, 1)
	struct ChatMember {
	private:
		enum Type : char {
			None = 0,
		    String = 1,
		    Int32 = 2,
		    Float32 = 3,
		    Pointer = 4,
		    WideString = 5,
		    Color = 6,
		    UInt64 = 7,
		    End = 8
		};
		
		Type None_;
		char MessageObject_[sizeof("MessageObject")];
		
		Type UInt64_;
		char steamid_[sizeof("steamid")];
		
	public:
		SteamID steamID;
		
	private:
		Type Int32_;
		char Permissions_[sizeof("Permissions")];
		
	public:
		EChatPermission permissions;
		
	private:
		Type Int32__;
		char Details_[sizeof("Details")];
		
	public:
		EClanPermission rank;
		
	private:
		Type End_;
		Type End__;
	};
#pragma pack(pop)

	class SteamClient {
    private:
        boost::asio::io_context & io;
	public:
		/**
		 * @param write         Called when SteamClient wants to send some data over the socket.
		 *                      Allocate a buffer of @a length bytes, then call @a fill with it, then send it.
		 * @param set_interval  @a callback must be called every @a timeout seconds as long as the connection is alive.
		 */
		SteamClient(boost::asio::io_context & _io, const Environment & e);


		/**
		 * Call when a connection has been established.
		 * 
		 * @return The number of bytes SteamClient expects next.
		 */
		std::size_t connected();
		
		/**
		 * Call when data has been received.
		 * 
		 * @param buffer    Must be of the length previously returned by #connected or #readable.
		 */
        void readable(std::unique_ptr<CMPacket> && data, const boost::system::error_code & ec, std::size_t size);
		
		
		/**
		 * Encryption handshake complete – it's now safe to log on.
		 */
		std::function<void()> onHandshake;

		/**
		 * All messages get passed to this handler
		 */
		 std::function<void(EMsg emsg, const unsigned char* data, std::size_t length, std::uint64_t job_id)> customHandler;

		/**
		 * @a steamID is your SteamID.
		 */
		std::function<void(EResult result, SteamID steamID, uint32_t cellid)> onLogOn;
		
		std::function<void(EResult result)> onLogOff;

		std::function<void(uint64_t)> onSessionToken;
		
		std::function<void(const unsigned char hash[20])> onSentry;

        std::string myUniqueId;

        std::string noonce;

        SteamApi api;

		void SetGamePlayed(int gameID);
        void SetGamePlayed(std::string name);

		template <typename T>
		void SendCMsg(T & Proto, EMsg eMsg);
		/**
		 * Each parameter except @a user is optional and will equal @c nullptr if unset.
		 */
		std::function<void(
			SteamID user,
			SteamID* source,
			const char* name,
			EPersonaState* state,
			const unsigned char avatar_hash[20],
			const char* game_name
		)> onUserInfo;
		
		/**
		 * Should be called in response to #JoinChat.
		 */
		std::function<void(
			SteamID room,
			EChatRoomEnterResponse response,
			const char* name,
			std::size_t member_count,
			const ChatMember members[]
		)> onChatEnter;
		
		/**
		 * @a member is invalid unless @a state_change == @c EChatMemberStateChange::Entered.
		 */
		std::function<void(
			SteamID room,
			SteamID acted_by,
			SteamID acted_on,
			EChatMemberStateChange state_change,
			const ChatMember* member
		)> onChatStateChange;
		
		std::function<void(SteamID room, SteamID chatter, const char* message)> onChatMsg;
		
		std::function<void(SteamID user, const char* message)> onPrivateMsg;
		
		std::function<void(SteamID user)> onTyping;
		
		std::function<void(
			bool incremental,
			std::map<SteamID, EFriendRelationship> &users,
			std::map<SteamID, EClanRelationship> &groups
		)> onRelationships;

		/***
		 * called when web cookies are acquired, vector contains all cookies
		 */
		std::function<void(std::vector<std::string>& cookies, std::string & sessionid)> onWebSession;

		std::string sessionID;

		/**
		 * @return true if EMsg was handled
		 */
        std::function<bool(EMsg emsg, const unsigned char* data, std::size_t length, std::uint64_t job_id)> defaultHandler;
		
		/**
		 * Call this after the encryption handshake. @a steamID is only needed if you are logging into a non-default instance.
		 * 
		 * @see onHandshake
		 */
		void LogOn(
			const char* username,
			const char* password,
			const char* code = nullptr,
			SteamID steamID = 0
		);
		
		void SetPersonaState(EPersonaState state);
        void SetPersona(EPersonaState state, const char * name);
		/**
		 * @see onChatEnter
		 */
		void JoinChat(SteamID chat);
		
		void LeaveChat(SteamID chat);
		
		void SendChatMessage(SteamID chat, const char* message);
		
		void SendPrivateMessage(SteamID user, const char* message);
		
		void SendTyping(SteamID user);
		
		/**
		 * @see onUserInfo
		 */
		void RequestUserInfo(std::size_t count, SteamID users[]);

		void webLogOn();

        void run();

        void setSentry(std::string && sentry);
        void setSentry(const std::string & sentry);
        void setCellid(std::string && cellid);
        void setCellid(const std::string & cellid);
        void setServerList(std::vector<net::endpoint> && serverList);
	private:

        net::socket sock;
        std::string sentry;
        std::string cellid;
		CMClient cmClient;

        std::array<unsigned char, 8> sock_read_buff = {0};

        std::queue<CMPacket> packet_queue;
        std::counting_semaphore<255> packet_sem;


        void steamWrite(std::size_t length, std::function<void(unsigned char* buffer)> fill);

        std::vector<net::endpoint> serverList;
        net::endpoint * ourServer = nullptr;
        void connect();
        void pickServer();
        bool finishConnection();
        void reconnect();

        std::unique_ptr<boost::asio::steady_timer> setInterval(std::function<void()> callback, int interval);
        static void runInterval(const boost::system::error_code&, std::function<void()> callback, int interval, boost::asio::steady_timer * timer);
		void ReadMessage(const unsigned char* data, uint32_t length);
		void HandleMessage(EMsg eMsg, const unsigned char* data, uint32_t length, std::uint64_t job_id);
        void _webAuthenticate(const std::string& nonce);
    };
}