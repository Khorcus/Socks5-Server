#include "session/client_session.hpp"
#include "session/server_session.hpp"
#include "config/config.hpp"
#include "crypto/crypto.hpp"

using namespace socks;

void usage() {
    std::cerr << "Usage for server: server s <server port> <buffer size> <timeout> <secret key> <iv>"
              << std::endl;
    std::cerr
            << "Usage for client: client c <client port> <buffer size> <timeout> "
               "<secret key> <iv> <server ip> <server port>"
            << std::endl;
}

int main(int argc, char *argv[]) {
    try {
        if (argc < 7) {
            usage();
            return 1;
        }
        std::size_t buffer_size(std::stoi(argv[3]));
        std::size_t timeout(std::stoi(argv[4]));
        std::vector<uint8_t> secret_key(argv[5], argv[5] + 256);
        std::vector<uint8_t> iv(argv[6], argv[6] + 128);

        io_context context;
        boost::asio::signal_set stop_signals(context, SIGINT, SIGTERM);
        stop_signals.async_wait([&](error_code ec, auto) {
            if (ec) {
                return;
            }
            context.stop();
        });

        if (!strcmp(argv[1], "s")) {
            uint16_t server_port(std::stoi(argv[2]));
            server_config config(buffer_size, timeout, secret_key, iv, server_port);

            spawn(context, [&context, config](const yield_context &yield) {
                tcp::acceptor acceptor{context};
                tcp::endpoint ep{tcp::v4(), config.server_port};
                acceptor.open(ep.protocol());
                acceptor.bind(ep);
                acceptor.listen();
                for (;;) {
                    tcp::socket server_socket{make_strand(acceptor.get_executor())};
                    tcp::socket remote_socket{make_strand(context)};
                    error_code ec;
                    acceptor.async_accept(server_socket, yield[ec]);
                    if (ec == boost::asio::error::operation_aborted) {
                        return;
                    }
                    if (ec)
                        std::cerr << "Failed to accept connection: " << ec.message() << std::endl;
                    if (!ec) {
                        std::make_shared<server_session>(
                                std::move(server_socket),
                                std::move(remote_socket),
                                config
                        )->start();
                    }
                }
            });


        } else if (!strcmp(argv[1], "c") && argc == 9) {
            uint16_t client_port(std::stoi(argv[2]));
            std::string server_ip(argv[7]);
            uint16_t server_port(std::stoi(argv[8]));
            client_config config(buffer_size, timeout, secret_key, iv, server_port, server_ip, client_port);

            spawn(context, [&context, config](const yield_context &yield) {
                tcp::acceptor acceptor{context};
                tcp::endpoint ep{tcp::v4(), config.client_port};
                acceptor.open(ep.protocol());
                acceptor.bind(ep);
                acceptor.listen();
                for (;;) {
                    tcp::socket client_socket{make_strand(acceptor.get_executor())};
                    tcp::socket server_socket{make_strand(context)};
                    error_code ec;
                    acceptor.async_accept(client_socket, yield[ec]);
                    if (ec == boost::asio::error::operation_aborted) {
                        return;
                    }
                    if (ec)
                        std::cerr << "Failed to accept connection: " << ec.message() << std::endl;
                    if (!ec) {
                        std::make_shared<client_session>(
                                std::move(client_socket),
                                std::move(server_socket),
                                config
                        )->start();
                    }
                }
            });
        } else {
            usage();
            return 1;
        }


        context.run();
    }
    catch (...) {
        std::cerr << boost::current_exception_diagnostic_information() << std::endl;
        return 1;
    }
}