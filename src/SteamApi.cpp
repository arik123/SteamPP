//
// Created by Max on 23. 3. 2021.
//

#include "../include/SteamApi.h"

#include <utility>
#include <cryptopp/gzip.h>
#include <utility>
#include "../include/utils.h"
#include <boost/asio.hpp>
#include "boost/certify/https_verification.hpp"

void SteamApi::GetCMList(const std::string &cellid, const std::function<void(std::vector < net::endpoint > )> &callback) {
    request("ISteamDirectory", "GetCMList", "v1", false,
            { {"cellid", cellid}, {"maxcount", "5"} },
            [=](http::response<http::string_body>& resp) {
                if (resp[http::field::content_type].starts_with("application/json"))
                {
                    rapidjson::Document document;
                    document.ParseInsitu(resp.body().data());
                    std::vector<net::endpoint> serverList;
                    serverList.reserve(document["response"]["serverlist"].GetArray().Size());
                    for (auto& v : document["response"]["serverlist"].GetArray())
                    {
                        std::string server(v.GetString(), v.GetStringLength());
                        serverList.emplace_back(asio::ip::address::from_string(server.substr(0, server.find(':'))), std::stoi(server.substr(server.find(':')+1)));
                    }
                    callback(serverList);
                }
                else
                {
                    callback({});
                }
            });
}

void SteamApi::request(const char *interface, const char *method, const char *version, bool post,
                       const std::unordered_map <std::string, std::variant<std::string, std::vector<uint8_t>>> &data,
                       const std::function<void(http::response < http::string_body >&)> &callback) {
    // Set SNI Hostname (many hosts need this to handshake successfully)
    std::string endpoint = "/";
    endpoint += interface;
    endpoint += '/';
    endpoint += method;
    endpoint += '/';
    endpoint += version;
    endpoint += '/';
    if(!data.empty()){
        auto iter = data.begin();
        std::string formData;
        while (true) {
            formData += urlEncode(iter->first);
            formData += '=';
            if(std::get_if<std::string>(&(iter->second))) {
                formData += urlEncode(std::get<std::string>(iter->second));
            } else {
                formData += urlEncode(std::get<std::vector<uint8_t>>(iter->second));
            }
            iter++;
            if (iter == data.end()) break;
            formData += '&';
        }
        if(post) {
            req_.body() = formData;
            req_.set(http::field::content_type, "application/x-www-form-urlencoded");
            std::cout << formData << std::endl;
            /*endpoint += '?';
            endpoint += "key=";
            endpoint += apiKey;
            endpoint += "&steamid=76561199057848043";*/
        } else {
            endpoint += '?';
            endpoint += formData;
        }
    }
    // Set up an HTTP GET request message
    req_.method(post ? http::verb::post : http::verb::get);
    req_.target(endpoint.c_str());
    req_.set(http::field::host, host);
    //req_.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    req_.set(http::field::user_agent, "Valve/Steam HTTP Client 1.0");
    req_.set(http::field::accept, "text/html,*/*;q=0.9");
    req_.set(http::field::accept_encoding, "gzip,identity,*;q=0");
    req_.set(http::field::accept_charset, "ISO-8859-1,utf-8,*;q=0.7");
    req_.set(http::field::connection, "close");
    req_.version(11);
    req_.prepare_payload();
    auto p_apiRequest = new WebRequest(ex, ctx, host, endpoint, req_, [callback](http::response<http::string_body>& resp){
            if(resp[http::field::content_encoding] == "gzip") { // unpack gunzip
                std::string decompressed;
                CryptoPP::Gunzip decomp(new CryptoPP::StringSink(decompressed));
                decomp.Put((uint8_t *) resp.body().data(), resp.body().size());
                decomp.MessageEnd();
                resp.body() = decompressed;
            }
            callback(resp);
        },
        [](WebRequest* ptr) {shutdown(ptr); });
    // Look up the domain name
    resolver_.async_resolve(host, "443", [p_apiRequest](beast::error_code ec, const net::resolver::results_type& results) {p_apiRequest->on_resolve(ec, results); });
}

SteamApi::SteamApi(const asio::any_io_executor &ex, std::string apiKey)
        : resolver_(ex), ex(ex), apiKey(std::move(std::move(apiKey))), ctx(ssl::context::tlsv12_client) {
    // This holds the root certificate used for verification
    ctx.set_verify_mode(ssl::context::verify_peer |
                        ssl::context::verify_fail_if_no_peer_cert);
    ctx.set_default_verify_paths();
    boost::certify::enable_native_https_server_verification(ctx); //FIXME: deprecated
}

void SteamApi::shutdown(WebRequest * ptr) {
    delete ptr;
}
