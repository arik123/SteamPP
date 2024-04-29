//
// Created by Max on 23. 3. 2021.
//

#include "../include/WebRequest.h"

#include <utility>
#include "../include/utils.h"
#include "../include/consoleColor.h"

void WebRequest::on_read(beast::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec)
        return fail(ec, "read");
    auto fields = req_.base();
    std::cout << color(colorFG::Bright_Blue) << printHttpMessage(req_).str() << printHttpMessage(res_).str() << color(colorFG::Default) << std::endl;
    callback(res_);

    // Set a timeout on the operation
    beast::get_lowest_layer(sslStream_).expires_after(std::chrono::seconds(30));

    // Gracefully close the stream
    if(ssl) sslStream_.async_shutdown([&](beast::error_code ec){on_shutdown(ec);});
    else {
        beast::get_lowest_layer(sslStream_).release_socket(); // is it needed ?
        shutdown_cb(this);
    }
}

void WebRequest::on_shutdown(beast::error_code ec) {
    if (ec == asio::error::eof) {
        // Rationale:
        // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
        ec = {};
    }
    if (ec)
        return fail(ec, "shutdown");

    // If we get here then the connection is closed gracefully
    shutdown_cb(this);
}

void WebRequest::on_write(beast::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec)
        return fail(ec, "write");

    // Receive the HTTP response
    if(ssl) http::async_read(sslStream_, buffer_, res_, [&](beast::error_code ec, std::size_t bt){on_read(ec, bt);});
    else    http::async_read(beast::get_lowest_layer(sslStream_), buffer_, res_, [&](beast::error_code ec, std::size_t bt){on_read(ec, bt);});
}

void WebRequest::on_handshake(beast::error_code ec) {
    if (ec)
        return fail(ec, "handshake");

    // Set a timeout on the operation
    beast::get_lowest_layer(sslStream_).expires_after(std::chrono::seconds(30));

    // Send the HTTP request to the remote
    if(ssl) http::async_write(sslStream_, req_, [&](beast::error_code ec, std::size_t bt){on_write(ec, bt);});
    else http::async_write(beast::get_lowest_layer(sslStream_), req_, [&](beast::error_code ec, std::size_t bt){on_write(ec, bt);});
}

void WebRequest::on_connect(beast::error_code ec, const asio::ip::basic_endpoint<asio::ip::tcp> &) {
    if (ec)
        return fail(ec, "connect");

    // Perform the SSL handshake
    if(ssl) sslStream_.async_handshake(ssl::stream_base::client, [&](beast::error_code ec){on_handshake(ec);});
    else on_handshake(ec);
}

void WebRequest::on_resolve(beast::error_code ec,
                            const asio::ip::basic_resolver<asio::ip::tcp, asio::any_io_executor>::results_type &results) {
    if (ec)
        return fail(ec, "resolve");
    if(ssl){
        if (!SSL_set_tlsext_host_name(sslStream_.native_handle(), host.data())) {
            beast::error_code ec2{static_cast<int>(::ERR_get_error()), asio::error::get_ssl_category()};
            std::cerr << ec2.message() << "\n";
            return;
        }
    }
    // Set a timeout on the operation
    beast::get_lowest_layer(sslStream_).expires_after(std::chrono::seconds(30));

    // Make the connection on the IP address we get from a lookup
    beast::get_lowest_layer(sslStream_).async_connect(results,
                                                      [&](beast::error_code ec, const net::resolver::results_type::endpoint_type& et){on_connect(ec, et);});
}

WebRequest::WebRequest(asio::any_io_executor ex, ssl::context &ctx, std::string_view host, std::string_view endpoint,
                       http::request<http::string_body> req,
                       std::function<void(http::response<http::string_body>&)>  callback,
                       std::function<void(WebRequest*)> shutdown_cb,
                       bool ssl)
        : sslStream_(ex, ctx), host(host), endpoint(endpoint), callback(std::move(callback)), shutdown_cb(std::move(shutdown_cb)), ssl(ssl){
    req_ = std::move(req);
}
