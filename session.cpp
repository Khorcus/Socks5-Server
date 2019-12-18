#include "session.hpp"

namespace socks {
    //TODO: Спросить про strand и conext
    session::session(io_context &context, tcp::socket socket, std::size_t buffer_size, std::size_t timeout)
            : client_socket(std::move(socket)),
              remote_socket(context),
              strand(context.get_executor()),
              client_buf(buffer_size),
              timer(context),
              resolver(context),
              buffer_size(buffer_size),
              timeout(timeout) {
    }

    void session::start() {
        auto self(shared_from_this());
        spawn(strand, [self](const yield_context &yield) {
            try {
                error_code ec;
                self->timer.expires_from_now(std::chrono::seconds(self->timeout));
                async_read(self->client_socket, buffer(self->client_buf, 2), yield[ec]);
                if (ec) {
                    if (ec != operation_aborted && (ec != eof)) {
                        std::cerr << "Failed to read connection request: " << ec.message() << std::endl;
                    }
                    return;
                }
                if (self->client_buf[0] != 0x05) {
                    std::cout << "Connection request with unsupported VER: " << (uint8_t) self->client_buf[0]
                              << std::endl;
                    return;
                }
                uint8_t num_methods = self->client_buf[1];
                async_read(self->client_socket, buffer(self->client_buf, num_methods), yield[ec]);
                if (ec) {
                    if (ec != operation_aborted && (ec != eof)) {
                        std::cerr << "Failed to read connection request: " << ec.message() << std::endl;
                    }
                    return;
                }
                for (uint8_t method = 0; method < num_methods; ++method) {
                    if (self->client_buf[method] == 0x00) {
                        self->connect_answer[1] = 0x00;
                        break;
                    }
                }
                async_write(self->client_socket, buffer(self->connect_answer, 2), yield[ec]);
                if (self->client_buf[1] == 0xFF) {
                    std::cout << "Connection request with unsupported METHOD: "
                              << (uint8_t) self->client_buf[1]
                              << std::endl;
                    return;
                }
                if (ec) {
                    if (ec != operation_aborted) {
                        std::cerr << "Failed to write connection response: " << ec.message() << std::endl;
                    }
                    return;
                }
                async_read(self->client_socket, buffer(self->client_buf, 4), yield[ec]);
                if (ec) {
                    if (ec != operation_aborted && (ec != eof)) {
                        std::cerr << "Failed to read command request: " << ec.message() << std::endl;
                    }
                    return;
                }
                if (self->is_command_request_valid()) {
                    if (self->client_buf[3] == 0x03) {
                        async_read(self->client_socket, buffer(self->client_buf, 1), yield[ec]);
                        if (ec) {
                            if (ec != operation_aborted && (ec != eof)) {
                                std::cerr << "Failed to read command request: " << ec.message() << std::endl;
                            }
                            return;
                        }
                        uint8_t domain_name_length = self->client_buf[0];
                        async_read(self->client_socket, buffer(self->client_buf, domain_name_length + 2), yield[ec]);
                        if (ec) {
                            if (ec != operation_aborted && (ec != eof)) {
                                std::cerr << "Failed to read command request: " << ec.message() << std::endl;
                            }
                            return;
                        }
                        self->resolve_domain_name(yield, ec, domain_name_length);
                    } else {
                        async_read(self->client_socket, buffer(self->client_buf, 6), yield[ec]);
                        if (ec) {
                            if (ec != operation_aborted && (ec != eof)) {
                                std::cerr << "Failed to read command request: " << ec.message() << std::endl;
                            }
                            return;
                        }
                        self->ep = tcp::endpoint(address_v4(endian_reverse(*((uint32_t *) &self->client_buf[0]))),
                                                 endian_reverse(*((uint16_t *) &self->client_buf[4])));
                    }
                }
                if (self->command_answer[1] == 0x00) {
                    std::cout << "Connecting to remote server: " << self->endpoint_to_string() << std::endl;
                    self->remote_socket.async_connect(self->ep, yield[ec]);
                    if (ec) {
                        //TODO: Спросить про то, какой код выставить
                        self->command_answer[1] = 0x03;
                    }
                }
                if (self->command_answer[1] == 0x00) {
                    uint32_t real_local_ip = endian_reverse(
                            self->remote_socket.local_endpoint().address().to_v4().to_uint());
                    uint16_t real_local_port = endian_reverse(self->remote_socket.local_endpoint().port());
                    std::memcpy(&self->command_answer[4], &real_local_ip, 4);
                    std::memcpy(&self->command_answer[8], &real_local_port, 2);
                }
                async_write(self->client_socket, buffer(self->command_answer, 10), yield[ec]);
                if (ec) {
                    if (ec != operation_aborted) {
                        std::cerr << "Failed to write command response" << std::endl;
                    }
                    return;
                }
                // копию shared ptr
                boost::asio::spawn(self->strand, [self](const yield_context &yield) {
                    self->echo(self->client_socket, self->remote_socket, yield);
                });
                self->echo(self->remote_socket, self->client_socket, yield);
            }
            catch (std::exception &e) {
                std::cerr << "Exception: " << e.what();
                self->client_socket.close();
                self->remote_socket.close();
                self->timer.cancel();
            }
        });

        boost::asio::spawn(strand, [self](const boost::asio::yield_context &yield) {
            error_code ec;
            while (self->client_socket.is_open()) {
                boost::system::error_code ignored_ec;
                self->timer.async_wait(yield[ignored_ec]);
                if (self->timer.expires_from_now() <= std::chrono::seconds(0)) {
                    std::cout << "Close connection with " << self->socket_to_string(self->client_socket, ec)
                              << std::endl;
                    self->client_socket.close();
                }
            }
        });
    }

    void session::echo(tcp::socket &src_socket, tcp::socket &dst_socket, const yield_context &yield) {
        error_code ec;
        std::vector<uint8_t> buf(buffer_size);
        for (;;) {
            std::size_t n = src_socket.async_read_some(buffer(buf), yield[ec]);
            //TODO: Спросить, правильно ли
            if (ec) {
                return;
            }
            dst_socket.async_write_some(boost::asio::buffer(buf, n), yield[ec]);
            if (ec) {
                return;
            }
        }
    }

    bool session::is_command_request_valid() {
        if (client_buf[2] != 0x00) {
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

    void session::resolve_domain_name(const yield_context &yield, error_code ec, uint8_t domain_name_length) {
        std::string remote_host(client_buf.begin(), client_buf.begin() + domain_name_length);
        std::string remote_port = std::to_string(endian_reverse(*((uint16_t *) &client_buf[domain_name_length])));
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

    std::string session::socket_to_string(tcp::socket &socket, error_code ec) {
        tcp::endpoint endpoint = client_socket.remote_endpoint(ec);
        if (ec) {
            return "closed socket";
        }
        return endpoint.address().to_string() + " " + std::to_string(endian_reverse(endpoint.port()));

    }

    std::string session::endpoint_to_string() {
        return ep.address().to_string() + " " +
               std::to_string(endian_reverse(ep.port()));
    }
}

