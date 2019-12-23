#include "session/client_session.hpp"
#include "session/server_session.hpp"
#include "config/config.hpp"

using namespace socks;

void usage() {
    std::cerr << "Usage for server: server <buffer size> <timeout> <secret key> <server port>"
              << std::endl;
    std::cerr
            << "Usage for client: client <buffer size> <timeout> <secret key> <server port> <server ip> <client port>"
            << std::endl;
}

int main(int argc, char *argv[]) {
    try {
        if (argc < 6) {
            usage();
            return 1;
        }
        std::size_t buffer_size(std::stoi(argv[2]));
        std::size_t timeout(std::stoi(argv[3]));
        std::string secret_key(argv[4]);
        uint16_t server_port(std::stoi(argv[5]));

        io_context context;
        boost::asio::signal_set stop_signals(context, SIGINT, SIGTERM);
        stop_signals.async_wait([&](error_code ec, auto) {
            if (ec) {
                return;
            }
            context.stop();
        });

        if (!strcmp(argv[1], "s")) {
            server_config config(buffer_size, timeout, secret_key, server_port);

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


        } else if (!strcmp(argv[1], "c") && argc == 8) {
            std::string server_ip(argv[6]);
            uint16_t client_port(std::stoi(argv[7]));
            client_config config(buffer_size, timeout, secret_key, server_port, server_ip, client_port);

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