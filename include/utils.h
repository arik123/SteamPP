#ifndef STEAMBOT_UTILS_H
#define STEAMBOT_UTILS_H
#include <string>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
namespace beast = boost::beast;
std::string urlEncode(const std::string& SRC);
std::string urlEncode(const std::vector<uint8_t>& SRC);
void fail(beast::error_code ec, char const *what);
std::ostringstream printHttpMessage(beast::http::request<beast::http::string_body> & msg);
std::ostringstream printHttpMessage(beast::http::response<beast::http::string_body> & msg);
#endif