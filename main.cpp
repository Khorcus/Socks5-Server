#include "session.hpp"

using namespace socks;

int main(int argc, char *argv[]) {
    try {
        if (argc != 4) {
            std::cerr << "Usage: echo_server <port> <buffer size> <timeout>\n";
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
                      error_code ec;
                      acceptor.async_accept(socket, yield[ec]);
                      if (ec == boost::asio::error::operation_aborted) {
                          return;
                      }
                      if (ec)
                          std::cerr << "Failed to accept connection: " << ec.message() << std::endl;
                      if (!ec) {
                          std::make_shared<session>(context, std::move(socket), buffer_size, timeout)->start();
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