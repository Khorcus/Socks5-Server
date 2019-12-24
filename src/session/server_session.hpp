#ifndef SOCKS5_SERVER_SERVER_SESSION_HPP
#define SOCKS5_SERVER_SERVER_SESSION_HPP

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
#include "../crypto/crypto.hpp"

namespace socks {

    using boost::asio::ip::tcp;
    using boost::asio::ip::address_v4;
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


    class server_session : public std::enable_shared_from_this<server_session> {
    public:
        explicit server_session(tcp::socket client_socket, tcp::socket remote_socket, const server_config &config);

        void start();

    private:

        void echo_from_client(const yield_context &yield);

        void echo_to_client(const yield_context &yield);

        void resolve_domain_name(const yield_context &yield, error_code ec);

        std::string socket_to_string(tcp::socket &socket, error_code ec);

        std::string endpoint_to_string();

        tcp_stream client_stream;
        tcp_stream remote_stream;
        std::vector<uint8_t> client_buf;
        uint8_t answer[10] = {0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        tcp::endpoint ep;
        tcp::resolver resolver;
        uint8_t client_message_length;
        crypto c;
        std::size_t offset;
        std::size_t buffer_size;
        std::size_t enc_buffer_size;
        std::size_t content_size;
        std::chrono::seconds timeout;
    };
}

#endif //SOCKS5_SERVER_SERVER_SESSION_HPP
