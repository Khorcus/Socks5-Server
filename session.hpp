#ifndef SOCKS5_SERVER_SESSION_HPP
#define SOCKS5_SERVER_SESSION_HPP

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <boost/endian/conversion.hpp>
#include <iostream>
#include <memory>

namespace socks {

    using boost::asio::ip::tcp;
    using boost::asio::ip::address_v4;
    using boost::asio::yield_context;
    using boost::asio::io_context;
    using boost::asio::async_write;
    using boost::asio::buffer;
    using boost::asio::error::operation_aborted;
    using boost::asio::error::eof;
    using boost::asio::spawn;
    using boost::system::error_code;
    using boost::endian::endian_reverse;


    class session : public std::enable_shared_from_this<session> {
    public:
        explicit session(io_context &context, tcp::socket socket, std::size_t buffer_size, std::size_t timeout);

        void start();

    private:

        void echo(tcp::socket &src_socket, tcp::socket &dst_socket, const yield_context &yield);

        bool is_command_request_valid(std::size_t n);

        void resolve_domain_name(const yield_context &yield, error_code ec);

        std::string socket_to_string(tcp::socket &socket, error_code ec);

        std::string endpoint_to_string();

        tcp::socket client_socket;
        tcp::socket remote_socket;
        boost::asio::strand<io_context::executor_type> strand;
        boost::asio::steady_timer timer;
        std::vector<uint8_t> client_buf;
        uint8_t connect_answer[2] = {0x05, 0xFF};
        uint8_t command_answer[10] = {0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        tcp::endpoint ep;
        tcp::resolver resolver;
        std::size_t buffer_size;
        std::size_t timeout;
    };
}


#endif //SOCKS5_SERVER_SESSION_HPP
