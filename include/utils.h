#pragma once
#include <string>
#include <unordered_map>
#include <fstream>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
namespace beast = boost::beast;
std::string urlEncode(const std::string& SRC);
std::string urlEncode(const std::vector<uint8_t>& SRC);
void fail(beast::error_code ec, char const *what);
std::ostringstream printHttpMessage(beast::http::request<beast::http::string_body> & msg);
std::ostringstream printHttpMessage(beast::http::response<beast::http::string_body> & msg);
std::string generateAuthCode(const std::string &secret);
class Environment {
    std::unordered_map<std::string, std::string> env;
public:
    Environment() : env() {
        std::ifstream dotEnv(".env");
        while(!dotEnv.eof()) {
            std::string line;
            char linePart [32];
            do {
                dotEnv.clear();
                dotEnv.getline(linePart, 32);
                line += linePart;
            } while (!dotEnv.eof() && !dotEnv.bad() && dotEnv.fail());
            int i = line.find('=');
            if( i >= 0) {
                if(line[line.length()-1] == '\r') line.resize(line.length()-1);
                env.insert({line.substr(0,i), std::string(line.c_str()+i+1)});
            }
        }
        dotEnv.close();
    }
    explicit Environment(char * envp[]) : Environment() {
        for (auto ienv = envp; *ienv != nullptr; ienv++)
        {
            std::string line = *ienv;
            int i = line.find('=');
            if( i >= 0) {
                env.insert({line.substr(0,i), std::string(line.c_str()+i+1)});
            }
        }
    }
    const std::string & get(const std::string & key) const {
        if(env.contains(key)) return env.at(key);
        else {
            char arr[64];
            snprintf(arr, 64, "Enviroment variable `%s` is not defined", key.c_str());
            throw std::runtime_error(arr);
        }
    }
};