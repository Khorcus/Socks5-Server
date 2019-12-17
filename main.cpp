#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <boost/endian/conversion.hpp>
#include <iostream>
#include <memory>

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
    explicit session(io_context &context, tcp::socket socket, std::size_t buffer_size, std::size_t timeout)
            : client_socket(std::move(socket)),
              remote_socket(context),
              strand(context.get_executor()),
              client_buf(buffer_size),
              timer(context),
              resolver(context),
              buffer_size(buffer_size),
              timeout(timeout) {
    }

    void start() {
        auto self(shared_from_this());
        spawn(strand, [this](const yield_context &yield) {
            try {
                error_code ec;
                timer.expires_from_now(std::chrono::seconds(15));
                std::size_t n = client_socket.async_read_some(buffer(client_buf, 258), yield[ec]);
                if (ec) {
                    if (ec != operation_aborted && (ec != eof || n)) {
                        std::cerr << "Failed to read connection request: " << ec.message() << std::endl;
                    }
                    return;
                }
                uint8_t num_methods = client_buf[1];
                if (n < 3 || n != num_methods + 2) {
                    std::cerr << "Invalid connection request" << std::endl;
                    return;
                }
                if (client_buf[0] != 0x05) {
                    std::cerr << "Connection request with unsupported VER: " << (uint8_t) client_buf[0]
                              << std::endl;
                    return;
                }
                for (uint8_t method = 0; method < num_methods; ++method) {
                    if (client_buf[2 + method] == 0x00) {
                        connect_answer[1] = 0x00;
                        break;
                    }
                }
                async_write(client_socket, buffer(connect_answer, 2), yield[ec]);
                if (client_buf[1] == 0xFF) {
                    std::cerr << "Connection request with unsupported METHOD: "
                              << (uint8_t) client_buf[1]
                              << std::endl;
                    return;
                }
                if (ec) {
                    if (ec != operation_aborted) {
                        std::cerr << "Failed to write connection response: " << ec.message() << std::endl;
                    }
                    return;
                }
                n = client_socket.async_read_some(buffer(client_buf, 261), yield[ec]);
                if (ec) {
                    if (ec != operation_aborted && (ec != eof || n)) {
                        std::cerr << "Failed to read command request: " << ec.message() << std::endl;
                    }
                    return;
                }
                if (is_command_request_valid(n)) {
                    if (client_buf[3] == 0x03) {
                        resolve_domain_name(yield, ec);
                    } else {
                        ep = tcp::endpoint(address_v4(ntohl(*((uint32_t *) &client_buf[4]))),
                                           ntohs(*((uint16_t *) &client_buf[8])));
                    }
                }
                if (command_answer[1] == 0x00) {
                    std::cout << "Connecting to remote server: " << ep.address().to_string() << std::endl;
                    remote_socket.async_connect(ep, yield[ec]);
                    if (ec) {
                        //TODO: Спросить про то, какой код выставить
                        command_answer[1] = 0x03;
                    }
                }
                if (command_answer[1] == 0x00) {
                    uint32_t real_local_ip = endian_reverse(remote_socket.local_endpoint().address().to_v4().to_uint());
                    uint16_t real_local_port = endian_reverse(remote_socket.local_endpoint().port());
                    std::memcpy(&command_answer[4], &real_local_ip, 4);
                    std::memcpy(&command_answer[8], &real_local_port, 2);
                }
                async_write(client_socket, buffer(command_answer, 10), yield[ec]);
                if (ec) {
                    if (ec != operation_aborted) {
                        std::cerr << "Failed to write command response" << std::endl;
                    }
                    return;
                }
                boost::asio::spawn(strand, [this](const yield_context &yield) {
                    echo(client_socket, remote_socket, yield);
                });
                echo(remote_socket, client_socket, yield);
            }
            catch (std::exception &e) {
                std::cout << "Exception: " << e.what();
                client_socket.close();
                remote_socket.close();
                timer.cancel();
            }
        });

        boost::asio::spawn(strand, [this, self](const boost::asio::yield_context &yield) {
            while (client_socket.is_open()) {
                boost::system::error_code ignored_ec;
                timer.async_wait(yield[ignored_ec]);
                if (timer.expires_from_now() <= std::chrono::seconds(0)) {
                    client_socket.close();
                }
            }
        });
    }

private:

    void echo(tcp::socket &src_socket, tcp::socket &dst_socket, const yield_context &yield) {
        error_code ec;
        std::vector<uint8_t> buf(buffer_size);
        for (;;) {
            std::size_t n = src_socket.async_read_some(buffer(buf), yield[ec]);
            //TODO: Спросить, правильно ли
            if (ec) {
                break;
            }
            dst_socket.async_write_some(boost::asio::buffer(buf, n), yield[ec]);
            if (ec) {
                break;
            }
        }
    }

    bool is_command_request_valid(std::size_t n) {
        if (n < 10 || client_buf[2] != 0x00) {
            std::cout << "Invalid command request" << std::endl;
            command_answer[1] = 0xFF;
            return false;
        }
        if (client_buf[0] != 0x05) {
            std::cerr << "Command request with unsupported VER: " << (uint8_t) client_buf[0] << std::endl;
            command_answer[1] = 0xFF;
            return false;
        }
        if (client_buf[1] != 0x01) {
            std::cout << "Command request with unsupported CMD: " << (uint8_t) client_buf[1] << std::endl;
            command_answer[1] = 0x07;
            return false;
        }
        if (client_buf[3] != 0x01 && client_buf[3] != 0x03) {
            std::cout << "Command request with unsupported ATYP: " << (uint8_t) client_buf[3] << std::endl;
            command_answer[1] = 0x08;
            return false;
        }
        return true;
    }

    void resolve_domain_name(const yield_context &yield, error_code ec) {
        uint8_t host_length = client_buf[4];
        std::string remote_host(client_buf.begin() + 5, client_buf.begin() + host_length + 5);
        std::string remote_port = std::to_string(endian_reverse(*((uint16_t *) &client_buf[5 + host_length])));
        tcp::resolver::query query(remote_host, remote_port);
        tcp::resolver::iterator endpoint_iterator = resolver.async_resolve(query, yield[ec]);
        if (ec) {
            std::cout << "Failed to resolve domain name" << std::endl;
            //TODO: Спросить про то, какой код выставить
            command_answer[1] = 0x03;
            return;
        }
        ep = *endpoint_iterator;
    }

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

int main(int argc, char *argv[]) {
    try {
        if (argc != 2) {
            std::cerr << "Usage: echo_server <port>\n";
            return 1;
        }
        io_context context;
        boost::asio::signal_set stop_signals(context, SIGINT, SIGTERM);
        stop_signals.async_wait([&](error_code ec, auto) {
            if (ec) {
                return;
            }
            context.stop();
        });

        spawn(context, [&context, port = std::atoi(argv[1])](const yield_context &yield) {
            tcp::acceptor acceptor{context};
            tcp::endpoint ep{tcp::v4(), (uint16_t) port};
            acceptor.open(ep.protocol());
            acceptor.bind(ep);
            acceptor.listen();
            for (;;) {
                tcp::socket socket{make_strand(acceptor.get_executor())};
                error_code ec;
                acceptor.async_accept(socket, yield[ec]);
                if (ec == boost::asio::error::operation_aborted) {
                    return;
                }
                if (ec)
                    std::cerr << "Failed to accept connection: " << ec.message() << std::endl;
                if (!ec) {
                    std::make_shared<session>(context, std::move(socket), 4096, 10)->start();
                }
            }
        });

        context.run();
    }
    catch (...) {
        std::cerr << boost::current_exception_diagnostic_information() << std::endl;
        return 1;
    }
}