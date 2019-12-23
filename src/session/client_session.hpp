#ifndef SOCKS5_SERVER_CLIENT_SESSION_HPP
#define SOCKS5_SERVER_CLIENT_SESSION_HPP

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/endian/conversion.hpp>
#include <iostream>
#include <memory>

#include "../config/config.hpp"


namespace socks {

    using boost::asio::ip::tcp;
    using boost::asio::ip::make_address_v4;
    using boost::asio::yield_context;
    using boost::asio::io_context;
    using boost::asio::async_write;
    using boost::asio::async_read;
    using boost::asio::buffer;
    using boost::asio::error::operation_aborted;
    using boost::asio::error::eof;
    using boost::asio::spawn;
    using boost::beast::tcp_stream;
    using boost::system::error_code;
    using boost::endian::big_to_native;


    class client_session : public std::enable_shared_from_this<client_session> {
    public:
        explicit client_session(tcp::socket client_socket, tcp::socket remote_socket, const client_config &config);

        void start();

    private:

        void
        echo(tcp_stream &src, tcp_stream &dst, const yield_context &yield, const std::shared_ptr<client_session> &self);

        bool is_command_request_valid();

        tcp_stream stream;
        tcp_stream server_stream;
        std::vector<uint8_t> client_buf;
        uint8_t connect_answer[2] = {0x05, 0xFF};
        uint8_t command_answer[10] = {0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        tcp::endpoint ep;
        tcp::resolver resolver;
        client_config config;
        uint8_t server_message_length;
    };
}


#endif //SOCKS5_SERVER_CLIENT_SESSION_HPP
