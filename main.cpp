#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <iostream>
#include <memory>

using boost::asio::ip::tcp;
typedef boost::asio::ip::address_v4 address_v4;


class session : public std::enable_shared_from_this<session> {
public:
    explicit session(boost::asio::io_context &io_context, tcp::socket socket, std::size_t buffer_size)
            : client_socket(std::move(socket)),
              remote_socket(io_context),
              timer(io_context),
              client_buf(buffer_size),
              strand(io_context.get_executor()) {
    }

    void echo(tcp::socket &src_socket, tcp::socket &dst_socket, const boost::asio::yield_context &yield) {
        boost::system::error_code err;
        std::vector<uint8_t> buf(client_buf.size());
        for (;;) {
            std::size_t n = src_socket.async_read_some(boost::asio::buffer(buf), yield[err]);
            if (err) {
                try {
                    dst_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_receive);
                } catch (std::exception &e) {
                    std::cerr << "Exception: " << e.what() << "\n";
                }
                break;
            }
            dst_socket.async_write_some(boost::asio::buffer(buf, n), yield[err]);
            if (err) {
                break;
            }
        }
    }

    void go() {
        auto self(shared_from_this());
        boost::asio::spawn(strand, [this, self](boost::asio::yield_context yield) {
            try {
                for (;;) {
                    boost::system::error_code ec;
                    timer.expires_from_now(std::chrono::seconds(15));
                    std::size_t bytes_read_count = client_socket.async_read_some(boost::asio::buffer(client_buf),
                                                                                 yield);
                    uint8_t num_methods = client_buf[1];
                    if (bytes_read_count < 3 || bytes_read_count != num_methods + 2) {
                        std::cout << "Invalid packet" << std::endl;
                        return;
                    }
                    if (client_buf[0] != 0x05) {
                        std::cout << "This server supports only SOCKS5" << std::endl;
                        return;
                    }
                    client_buf[1] = 0xFF;
                    for (uint8_t method = 0; method < num_methods; ++method) {
                        if (client_buf[2 + method] == 0x00) {
                            client_buf[1] = 0x00;
                            break;
                        }
                    }
                    client_socket.async_write_some(boost::asio::buffer(client_buf, 2), yield);
                    if (client_buf[1] == 0xFF) {
                        return;
                    }
                    bytes_read_count = client_socket.async_read_some(boost::asio::buffer(client_buf), yield);
                    if (bytes_read_count < 10) {
                        std::cout << "Invalid packet" << std::endl;
                        return;
                    }
                    if (client_buf[0] != 0x05) {
                        std::cout << "This server supports only SOCKS5" << std::endl;
                        return;
                    }
                    if (client_buf[1] != 0x01) {
                        std::cout << "This server supports only connect method" << std::endl;
                        return;
                    }
                    if (client_buf[2] != 0x00) {
                        std::cout << "Invalid packet" << std::endl;
                        return;
                    }
                    if (client_buf[3] != 0x01 && client_buf[3] != 0x03) {
                        std::cout << "This server doesn't support IPv6" << std::endl;
                        return;
                    }
                    tcp::endpoint ep;
                    if (client_buf[3] == 0x03) {
                        tcp::resolver resolver(strand);
                        uint8_t host_length = client_buf[4];
                        std::string remote_host(client_buf.begin() + 5, client_buf.begin() + host_length + 5);
                        std::string remote_port = std::to_string(ntohs(*((uint16_t *) &client_buf[5 + host_length])));
                        tcp::resolver::query query(remote_host, remote_port);
                        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
                        ep = *endpoint_iterator;
                        std::cout << remote_host << std::endl;
                        std::cout << ep.address().to_string() << std::endl;
                    } else {
                        ep = tcp::endpoint(address_v4(ntohl(*((uint32_t *) &client_buf[4]))),
                                           ntohs(*((uint16_t *) &client_buf[8])));
                    }
                    std::cout << "Connect..." << std::endl;
                    remote_socket.connect(ep);
                    if (ec) {
                        std::cout << "Failed to connect" << std::endl;
                        return;
                    }
                    client_buf[1] = 0x00;
                    client_buf[3] = 0x01;
                    uint32_t real_remote_ip = htonl(remote_socket.local_endpoint().address().to_v4().to_uint());
                    uint16_t real_remote_port = htons(remote_socket.local_endpoint().port());
                    std::memcpy(&client_buf[4], &real_remote_ip, 4);
                    std::memcpy(&client_buf[8], &real_remote_port, 2);
                    std::cout << remote_socket.local_endpoint().address().to_string() << " " << real_remote_port
                              << std::endl;
                    client_socket.async_write_some(boost::asio::buffer(client_buf, 10), yield);
                    boost::asio::spawn(strand, [&](const boost::asio::yield_context &yield) {
                        echo(std::ref(client_socket), std::ref(remote_socket), yield);
                    });
                    echo(remote_socket, client_socket, yield);
                }
            }
            catch (std::exception &e) {
                client_socket.close();
                remote_socket.close();
                timer.cancel();
            }
        });

        boost::asio::spawn(strand,
                           [this, self](const boost::asio::yield_context &yield) {
                               while (client_socket.is_open()) {
                                   boost::system::error_code ignored_ec;
                                   timer.async_wait(yield[ignored_ec]);
                                   if (timer.expires_from_now() <= std::chrono::seconds(0))
                                       client_socket.close();
                               }
                           });
    }

private:
    tcp::socket client_socket;
    tcp::socket remote_socket;
    boost::asio::steady_timer timer;
    boost::asio::strand<boost::asio::io_context::executor_type> strand;
    std::vector<uint8_t> client_buf;
};

int main(int argc, char *argv[]) {
    try {
        if (argc != 2) {
            std::cerr << "Usage: echo_server <port>\n";
            return 1;
        }

        boost::asio::io_context io_context;

        boost::asio::spawn(io_context,
                           [&](const boost::asio::yield_context &yield) {
                               tcp::acceptor acceptor(io_context,
                                                      tcp::endpoint(tcp::v4(), std::atoi(argv[1])));

                               for (;;) {
                                   boost::system::error_code ec;
                                   tcp::socket socket(io_context);
                                   acceptor.async_accept(socket, yield[ec]);
                                   if (!ec) {
                                       std::make_shared<session>(io_context, std::move(socket), 4096)->go();
                                   }
                               }
                           });

        io_context.run();
    }
    catch (std::exception &e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return 1;
    }
}