#include "client_session.hpp"

namespace socks {
    client_session::client_session(tcp::socket client_socket, tcp::socket remote_socket, const client_config &config)
            : stream(std::move(client_socket)),
              server_stream(std::move(remote_socket)),
              client_buf(config.buffer_size),
              resolver(client_socket.get_executor()),
              server_message_length(),
              c(config.secret_key, config.iv),
              offset(sizeof(std::size_t)),
              buffer_size(config.buffer_size),
              enc_buffer_size(buffer_size + 16),
              content_size(buffer_size - offset),
              timeout(config.timeout),
              server_ip(config.server_ip),
              server_port(config.server_port) {
    }

    void client_session::start() {
        auto self(shared_from_this());
        spawn(stream.get_executor(), [self](const yield_context &yield) {
            try {
                error_code ec;
                self->stream.expires_after(self->timeout);
                async_read(self->stream, buffer(self->client_buf, 2), yield[ec]);
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
                self->stream.expires_after(self->timeout);
                async_read(self->stream, buffer(self->client_buf, num_methods), yield[ec]);
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
                self->stream.expires_after(self->timeout);
                async_write(self->stream, buffer(self->connect_answer, 2), yield[ec]);
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
                self->stream.expires_after(self->timeout);
                async_read(self->stream, buffer(self->client_buf, 4), yield[ec]);
                if (ec) {
                    if (ec != operation_aborted && (ec != eof)) {
                        std::cerr << "Failed to read command request: " << ec.message() << std::endl;
                    }
                    return;
                }
                if (self->is_command_request_valid()) {
                    if (self->client_buf[3] == 0x03) {
                        self->stream.expires_after(self->timeout);
                        async_read(self->stream, buffer(self->client_buf, 1), yield[ec]);
                        if (ec) {
                            if (ec != operation_aborted && (ec != eof)) {
                                std::cerr << "Failed to read command request: " << ec.message() << std::endl;
                            }
                            return;
                        }
                        uint8_t domain_name_length = self->client_buf[0];
                        self->stream.expires_after(self->timeout);
                        async_read(self->stream, buffer(self->client_buf, domain_name_length + 2), yield[ec]);
                        self->server_message_length = domain_name_length + 2;
                        if (ec) {
                            if (ec != operation_aborted && (ec != eof)) {
                                std::cerr << "Failed to read command request: " << ec.message() << std::endl;
                            }
                            return;
                        }
                    } else {
                        self->stream.expires_after(self->timeout);
                        async_read(self->stream, buffer(self->client_buf, 6), yield[ec]);
                        self->server_message_length = 6;
                        if (ec) {
                            if (ec != operation_aborted && (ec != eof)) {
                                std::cerr << "Failed to read command request: " << ec.message() << std::endl;
                            }
                            return;
                        }
                    }
                    self->ep = tcp::endpoint(make_address_v4(self->server_ip), self->server_port);
                    self->server_stream.expires_after(self->timeout);
                    self->server_stream.async_connect(self->ep, yield[ec]);
                    if (ec) {
                        //TODO: Спросить про то, какой код выставить
                        self->command_answer[1] = 0x03;
                    }
                }
                if (self->command_answer[1] == 0x00) {
                    self->client_buf.insert(self->client_buf.begin(), self->server_message_length);
                    self->server_stream.expires_after(self->timeout);
                    async_write(self->server_stream, buffer(self->client_buf, self->server_message_length + 1),
                                yield[ec]);
                    if (ec) {
                        if (ec != operation_aborted) {
                            std::cerr << "Failed to write to server" << std::endl;
                        }
                        return;
                    }

                    self->server_stream.expires_after(self->timeout);
                    async_read(self->server_stream, buffer(self->command_answer, 10), yield[ec]);
                    if (ec) {
                        if (ec != operation_aborted) {
                            std::cerr << "Failed to read from server" << std::endl;
                        }
                        return;
                    }
                }
                self->stream.expires_after(self->timeout);
                async_write(self->stream, buffer(self->command_answer, 10), yield[ec]);
                if (ec) {
                    if (ec != operation_aborted) {
                        std::cerr << "Failed to write command response" << std::endl;
                    }
                    return;
                }
                boost::asio::spawn(self->stream.get_executor(), [self](const yield_context &yield) {
                    self->echo_to_server(yield);
                });
                self->echo_from_server(yield);
            }
            catch (std::exception &e) {
                std::cerr << "Exception: " << e.what();
                return;
            }
        });
    }

    void client_session::echo_from_server(const yield_context &yield) {
        error_code ec;
        for (;;) {
            std::vector<uint8_t> buf(enc_buffer_size);
            std::vector<uint8_t> dec_buf(enc_buffer_size);
            server_stream.expires_after(timeout);
            async_read(server_stream, buffer(buf, enc_buffer_size), yield[ec]);
            std::size_t n = reinterpret_cast<std::size_t *>(&buf[0])[0];
            std::cout << "from server " << n << std::endl;
            if (ec) {
                return;
            }
            if (n == 0) {
                return;
            }
            n = c.decrypt(buf.data() + offset, n, &dec_buf[0]);
            stream.expires_after(timeout);
            async_write(stream, boost::asio::buffer(dec_buf, n), yield[ec]);
            if (ec) {
                return;
            }
        }
    }

    void client_session::echo_to_server(const yield_context &yield) {
        error_code ec;
        for (;;) {
            std::vector<uint8_t> buf(content_size);
            std::vector<uint8_t> enc_buf(enc_buffer_size);
            stream.expires_after(timeout);
            std::size_t n = stream.async_read_some(buffer(buf), yield[ec]);
            if (ec) {
                return;
            }
            if (n == 0) {
                return;
            }
            n = c.encrypt(buf.data(), n, &enc_buf[offset]);
            std::cout << "to server " << n << std::endl;
            reinterpret_cast<std::size_t *>(&enc_buf[0])[0] = n;
            server_stream.expires_after(timeout);
            async_write(server_stream, boost::asio::buffer(enc_buf, enc_buffer_size), yield[ec]);
            if (ec) {
                return;
            }
        }
    }

    bool client_session::is_command_request_valid() {
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
}

