//
// Created by Max on 2. 4. 2021.
//

#include "../include/SteamCommunity.h"
#include "../include/utils.h"
#include "rapidjson/ostreamwrapper.h"
#include "rapidjson/writer.h"
#include "../include/consoleColor.h"

#undef _DEBUG_JSON

SteamCommunity::SteamCommunity(const asio::any_io_executor &ex)
        : resolver_(ex), ex(ex), ctx(ssl::context::tlsv12_client) {
    //TODO: duplicate

    // This holds the root certificate used for verification
    ctx.set_verify_mode(ssl::context::verify_peer |
                        ssl::context::verify_fail_if_no_peer_cert);
    ctx.set_default_verify_paths();
    boost::certify::enable_native_https_server_verification(ctx); //FIXME: deprecated
}

void SteamCommunity::request(std::string endpoint, bool post,
                             const std::unordered_map<std::string, std::variant<std::string, std::vector<uint8_t>>> &data,
                             std::string referer,
                             const std::function<void(http::response<http::string_body> &)> &callback) {
    // Set SNI Hostname (many hosts need this to handshake successfully)

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
        } else {
            endpoint += '?';
            endpoint += formData;
        }
    }
    if(!cookies.empty()){
        std::string cs;
        for(const auto & cookie : cookies){
            if(!cs.empty()) cs += "; ";
             cs += cookie;
        }
        std::cout << cs << std::endl;
        req_.set(http::field::cookie, cs);
    }
    // Set up an HTTP GET request message
    req_.set(http::field::user_agent, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36");
    req_.method(post ? http::verb::post : http::verb::get);
    req_.target(endpoint.c_str());
    req_.set(http::field::host, host);
    //req_.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    req_.set(http::field::accept, "*/*");
    req_.prepare_payload();
    if (referer.length()) {
        req_.set(http::field::referer, referer);
    }
    //req_.insert()
    req_.version(11);
    req_.prepare_payload();
    auto p_apiRequest = new WebRequest(ex,
                                       ctx,
                                       host,
                                       endpoint,
                                       req_,
                                       callback,
                                       [](WebRequest * ptr){shutdown(ptr);}, true);
    // Look up the domain name
    resolver_.async_resolve(host, "443", [p_apiRequest](beast::error_code ec, const net::resolver::results_type &results) {
        p_apiRequest->on_resolve(ec, results);
    });
}

void SteamCommunity::shutdown(WebRequest * ptr) {
    delete ptr;
}

void SteamCommunity::getUserInventory(uint64_t steamid, uint32_t appID, uint32_t contextID,
                                      const std::function<void(std::vector<InventoryItem> &)> &callback,
                                      const std::string &language, const std::string &start) {
    std::string endpoint("/inventory/");
    endpoint += std::to_string(steamid);
    endpoint += '/';
    endpoint += std::to_string(appID);
    endpoint += '/';
    endpoint += std::to_string(contextID);
    std::unordered_map<std::string, std::variant<std::string, std::vector<uint8_t>>> params = {{"l", language},
                                                           {"count", "5000"}};
    if (start.length()) {
        params.insert({"start_assetid", start});
    }
    request(endpoint,
            false, params,
            "",
            [callback](http::response<http::string_body> &resp) {
                std::vector<InventoryItem> inventory;
                std::cout << "inventory responded\n";
                if (resp.result_int() == 200 && resp[http::field::content_type].starts_with("application/json")) {
                    //TODO handle more than 5000 items
                    rapidjson::Document document;
                    document.Parse(resp.body().data());
                    std::cout << "Success " << document["success"].GetInt();
                    std::cout << ", Count " << document["total_inventory_count"].GetInt() << '\n' << color(colorFG::Bright_Blue);
                    for (rapidjson::Value::ConstValueIterator itr = document["assets"].Begin();
                         itr != document["assets"].End(); ++itr) {
#ifdef _DEBUG_JSON
                        rapidjson::OStreamWrapper out(std::cout);
                        rapidjson::Writer<rapidjson::OStreamWrapper> writer(out);
                        itr->Accept(writer);
                        std::cout << "\n\t";
#endif
                        InventoryItem item;
                        item.assetid = std::stoull(itr->operator[]("assetid").GetString());
                        item.amount = std::stoul(itr->operator[]("amount").GetString());
                        item.appid = itr->operator[]("appid").GetUint();
                        item.classid = std::stoull(itr->operator[]("classid").GetString());
                        item.contextid = std::stoull(itr->operator[]("classid").GetString());
                        for (rapidjson::Value::ConstValueIterator itr2 = document["descriptions"].Begin();
                             itr2 != document["descriptions"].End(); ++itr2) {
                            if (std::stoull(itr2->operator[]("classid").GetString()) != item.classid) continue;
#ifdef _DEBUG_JSON
                            rapidjson::Writer<rapidjson::OStreamWrapper> writer2(out);
                            itr2->Accept(writer2);
                            std::cout << '\n';
#endif
                            item.name = itr2->operator[]("name").GetString();
                            item.marketable = itr2->operator[]("marketable").GetInt();
                            item.tradable = itr2->operator[]("tradable").GetInt();
                            break;
                        }
                        inventory.push_back(item);
                    }
                    std::cout<< color();
                    callback(inventory);
                } else {
                    callback(inventory);
                }
            });
}