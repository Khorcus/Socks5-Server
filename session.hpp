#ifndef SOCKS5_SERVER_SESSION_HPP
#define SOCKS5_SERVER_SESSION_HPP

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
    using boost::endian::endian_reverse;


    class session : public std::enable_shared_from_this<session> {
    public:
        explicit session(tcp::socket client_socket, tcp::socket remote_socket, std::size_t buffer_size,
                         std::size_t timeout);

        void start();

    private:

        void echo(tcp_stream &src, tcp_stream &dst, const yield_context &yield, const std::shared_ptr<session>& self);

        bool is_command_request_valid();

        void resolve_domain_name(const yield_context &yield, error_code ec, uint8_t domain_name_length);

        std::string socket_to_string(tcp::socket &socket, error_code ec);

        std::string endpoint_to_string();

        tcp_stream client_stream;
        tcp_stream remote_stream;
        std::vector<uint8_t> client_buf;
        uint8_t connect_answer[2] = {0x05, 0xFF};
        uint8_t command_answer[10] = {0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        tcp::endpoint ep;
        tcp::resolver resolver;
        std::size_t buffer_size;
        std::chrono::seconds timeout;
    };
}


#endif //SOCKS5_SERVER_SESSION_HPP
