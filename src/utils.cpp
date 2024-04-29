#include "../include/utils.h"

#include <iostream>
#include <boost/beast/core/detail/base64.hpp>
#include <boost/endian.hpp>
#include <openssl/hmac.h>

std::string urlEncode(const std::string& SRC) {
    std::string ret;
    ret.reserve(SRC.size());
    for (std::string::const_iterator iter = SRC.begin(); iter != SRC.end(); ++iter) {
        std::string::value_type c = (*iter);
            // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            ret += c;
            continue;
        } else if(c == ' ') {
            ret+='+';
        }
        // Any other characters are percent-encoded
        char buff[4];
        sprintf(buff, "%%%02x", c);
        ret += buff;
    }
    return ret;
}
std::string urlEncode(const std::vector<uint8_t>& SRC) {
    std::string ret;
    ret.reserve(SRC.size());
    for (auto iter = SRC.begin(); iter != SRC.end(); ++iter) {
        uint8_t c = (*iter);
        char buff[4];
        sprintf(buff, "%%%02x", c);
        ret += buff;
    }
    return ret;
}

void fail(beast::error_code ec, char const *what){
    std::cerr << what << ": " << ec.message() << "\n";
}


std::ostringstream printHttpMessage(beast::http::request<beast::http::string_body> & msg) {
    std::ostringstream o;
    auto fields = msg.base();
    o << "Request\n";
    o << msg.method() << " " << msg.target() << '\n';
    for (const auto &field: fields) {
        o << field.name_string() << ": " << field.value() << '\n';
    }
    o << msg.body().data() << '\n';
    return o;
}
std::ostringstream printHttpMessage(beast::http::response<beast::http::string_body> & msg) {
    std::ostringstream o;
    auto fields = msg.base();
    o << "Response: " << msg.result_int() << " " << msg.result() << "\n";
    for (const auto &field: fields) {
        o << field.name_string() << ": " << field.value() << '\n';
    }
    //o << msg.body().data() << '\n';
    return o;
}


std::string generateAuthCode(const std::string &secret) {
    using namespace boost::beast::detail;
    std::vector<uint8_t> decoded;
    decoded.resize(base64::decoded_size(secret.size()));
    base64::decode(decoded.data(), secret.c_str(), secret.size());
    std::chrono::system_clock::time_point tp = std::chrono::system_clock::now();
    std::chrono::system_clock::duration dtn = tp.time_since_epoch();
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(dtn).count();
    now /= 1000;
    now /= 30;
    now = boost::endian::big_to_native(now);
    std::vector<uint8_t> out (EVP_MAX_MD_SIZE);
    uint32_t md_size;
    HMAC(EVP_sha1(), decoded.data(), decoded.size()-1, reinterpret_cast<uint8_t*>(&now), sizeof (now), out.data(), &md_size);
    out.resize(md_size);
    uint32_t partBuff = *reinterpret_cast<uint32_t *>(out.data() + (out[19] & 0xf));
    int b = out[19] & 0xF;
    int codePoint = (out[b] & 0x7F) << 24 | (out[b + 1] & 0xFF) << 16 | (out[b + 2] & 0xFF) << 8 | (out[b + 3] & 0xFF);
    const char * chars = "23456789BCDFGHJKMNPQRTVWXY";
    std::string code;
    for (int i = 0; i < 5; i++) {
        code += chars[codePoint % strlen(chars)];
        codePoint /= strlen(chars);
    }
    return code;
}