#include <thread>
#include "session.hpp"

using namespace socks;

template<typename F>
auto at_scope_exit(F &&f) {
    using f_t = std::remove_cvref_t<F>;
    static_assert(std::is_nothrow_destructible_v<f_t> &&
                  std::is_nothrow_invocable_v<f_t>);
    struct ase_t {
        F f;

        ase_t(F &&f)
                : f(std::forward<F>(f)) {}

        ase_t(const ase_t &) = default;

        ase_t(ase_t &&) = delete;

        ase_t operator=(const ase_t &) = delete;

        ase_t operator=(ase_t &&) = delete;

        ~ase_t() {
            std::forward<F>(f)();
        }
    };
    return ase_t{std::forward<F>(f)};
}

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

        std::vector<std::thread> thread_pool;
        std::size_t thread_count = std::atoi(argv[4]);
        thread_pool.reserve(thread_count);
        auto ase = at_scope_exit([&]() noexcept {
            for (auto &t:thread_pool) {
                t.join();
            }
        });
        for (size_t i = 0; i < thread_count; ++i)
            thread_pool.emplace_back([&] {
                context.run();
            });
        context.run();
    }
    catch (...) {
        std::cerr << boost::current_exception_diagnostic_information() << std::endl;
        return 1;
    }
}