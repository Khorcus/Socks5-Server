#include <thread>
#include "session.hpp"
#include <boost/bind.hpp>

using namespace socks;

int main(int argc, char *argv[]) {
    try {
        if (argc != 5) {
            std::cerr << "Usage: echo_server <port> <buffer size> <timeout> <thread_count>" << std::endl;
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

        spawn(context,
              [&context, port = std::atoi(argv[1]), buffer_size = std::atoi(argv[2]), timeout = std::atoi(argv[3])](
                      const yield_context &yield) {
                  tcp::acceptor acceptor{context};
                  tcp::endpoint ep{tcp::v4(), (uint16_t) port};
                  acceptor.open(ep.protocol());
                  acceptor.bind(ep);
                  acceptor.listen();
                  for (;;) {
                      tcp::socket socket{make_strand(acceptor.get_executor())};
                      tcp::socket remote_socket{make_strand(context)};
                      error_code ec;
                      acceptor.async_accept(socket, yield[ec]);
                      if (ec == boost::asio::error::operation_aborted) {
                          return;
                      }
                      if (ec)
                          std::cerr << "Failed to accept connection: " << ec.message() << std::endl;
                      if (!ec) {
                          std::make_shared<session>(std::move(socket), std::move(remote_socket), buffer_size,
                                                    timeout)->start();
                      }
                  }
              });

        std::vector<std::thread> threads;
        std::size_t thread_count = std::atoi(argv[4]);

        for (int n = 0; n < thread_count; ++n) {
            threads.emplace_back(boost::bind(&boost::asio::io_context::run, &context));
        }

        for (auto &thread : threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
    }
    catch (...) {
        std::cerr << boost::current_exception_diagnostic_information() << std::endl;
        return 1;
    }
}