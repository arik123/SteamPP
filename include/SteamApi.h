//
// Created by Max on 23. 3. 2021.
//
#pragma once
#ifndef STEAMBOT_STEAMAPI_H
#define STEAMBOT_STEAMAPI_H
#include <functional>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <utility>
#include <boost/beast/version.hpp>
#include <boost/asio/strand.hpp>
#include <variant>

#include "boost/certify/https_verification.hpp"
#include "WebRequest.h"
#include "rapidjson/document.h"

namespace asio = boost::asio;    // from <boost/asio.hpp>
namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using net = boost::asio::ip::tcp;    // from <boost/asio.hpp>

class SteamApi {
    static constexpr std::string_view host = "api.steampowered.com";
	net::resolver resolver_;
	asio::any_io_executor ex;
	ssl::context ctx;
	beast::flat_buffer buffer_; // (Must persist between reads)
	http::request<http::string_body> req_;
	http::response<http::string_body> res_;
	std::string apiKey;
	
	static void shutdown(WebRequest * ptr);
public:
	SteamApi(const asio::any_io_executor& ex, std::string apiKey);
	// Start the asynchronous operation
	void request(char const* interface, char const* method, char const* version, bool post, const std::unordered_map<std::string, std::variant<std::string, std::vector<uint8_t>>>& data, const std::function<void(http::response<http::string_body>&)>& callback);
	void GetCMList(const std::string& cellid, const std::function<void(std::vector<net::endpoint> serverList)>& callback);
};


#endif //STEAMBOT_STEAMAPI_H
