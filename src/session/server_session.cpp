#include "server_session.hpp"

namespace socks {
    server_session::server_session(tcp::socket client_socket, tcp::socket remote_socket, const server_config &config)
            : client_stream(std::move(client_socket)),
              remote_stream(std::move(remote_socket)),
              client_buf(config.buffer_size),
              resolver(client_socket.get_executor()),
              client_message_length(),
              c(config.secret_key, config.iv),
              offset(sizeof(std::size_t)),
              buffer_size(config.buffer_size),
              enc_buffer_size(buffer_size + 16),
              content_size(buffer_size - offset),
              timeout(config.timeout) {
    }

    void server_session::start() {
        auto self(shared_from_this());
        spawn(client_stream.get_executor(), [self](const yield_context &yield) {
            try {
                error_code ec;
                self->client_stream.expires_after(self->timeout);
                async_read(self->client_stream, buffer(self->client_buf, 1), yield[ec]);
                self->client_message_length = self->client_buf[0];
                if (ec) {
                    if (ec != operation_aborted && (ec != eof)) {
                        std::cerr << "Failed to read request: " << ec.message() << std::endl;
                    }
                    return;
                }
                if (self->client_message_length > 6) {
                    self->client_stream.expires_after(self->timeout);
                    async_read(self->client_stream, buffer(self->client_buf, self->client_message_length), yield[ec]);
                    if (ec) {
                        if (ec != operation_aborted && (ec != eof)) {
                            std::cerr << "Failed to read request: " << ec.message() << std::endl;
                        }
                        return;
                    }
                    self->resolve_domain_name(yield, ec);
                } else {
                    self->client_stream.expires_after(self->timeout);
                    async_read(self->client_stream, buffer(self->client_buf, 6), yield[ec]);
                    if (ec) {
                        if (ec != operation_aborted && (ec != eof)) {
                            std::cerr << "Failed to read request: " << ec.message() << std::endl;
                        }
                        return;
                    }
                    self->ep = tcp::endpoint(address_v4(big_to_native(*((uint32_t *) &self->client_buf[1]))),
                                             big_to_native(*((uint16_t *) &self->client_buf[5])));
                }
                std::cout << "Connecting to remote server: " << self->endpoint_to_string() << std::endl;
                self->remote_stream.expires_after(self->timeout);
                self->remote_stream.async_connect(self->ep, yield[ec]);
                if (ec) {
                    //TODO: Спросить про то, какой код выставить
                    self->answer[1] = 0x03;
                } else {
                    uint32_t real_local_ip = big_to_native(
                            self->remote_stream.socket().local_endpoint().address().to_v4().to_uint());
                    uint16_t real_local_port = big_to_native(self->remote_stream.socket().local_endpoint().port());
                    std::memcpy(&self->answer[4], &real_local_ip, 4);
                    std::memcpy(&self->answer[8], &real_local_port, 2);
                }
                self->client_stream.expires_after(self->timeout);
                async_write(self->client_stream, buffer(self->answer, 10), yield[ec]);
                if (ec) {
                    if (ec != operation_aborted) {
                        std::cerr << "Failed to write response" << std::endl;
                    }
                    return;
                }
                boost::asio::spawn(self->client_stream.get_executor(), [self](const yield_context &yield) {
                    self->echo_from_client(yield);
                });
                self->echo_to_client(yield);
            }
            catch (std::exception &e) {
                std::cerr << "Exception: " << e.what();
                return;
            }
        });
    }

    void server_session::echo_from_client(const yield_context &yield) {
        error_code ec;
        for (;;) {
            std::vector<uint8_t> buf(enc_buffer_size);
            std::vector<uint8_t> dec_buf(enc_buffer_size);
            client_stream.expires_after(timeout);
            async_read(client_stream, buffer(buf, enc_buffer_size), yield[ec]);
            std::size_t n = reinterpret_cast<std::size_t *>(&buf[0])[0];
            std::cout << "from client " << n << std::endl;
            if (ec) {
                return;
            }
            if (n == 0) {
                return;
            }
            n = c.decrypt(buf.data() + offset, n, &dec_buf[0]);
            remote_stream.expires_after(timeout);
            async_write(remote_stream, boost::asio::buffer(dec_buf, n), yield[ec]);
            if (ec) {
                return;
            }
        }
    }

    void server_session::echo_to_client(const yield_context &yield) {
        error_code ec;
        for (;;) {
            std::vector<uint8_t> buf(content_size);
            std::vector<uint8_t> enc_buf(enc_buffer_size);
            remote_stream.expires_after(timeout);
            std::size_t n = remote_stream.async_read_some(buffer(buf), yield[ec]);
            if (ec) {
                return;
            }
            if (n == 0) {
                return;
            }
            n = c.encrypt(buf.data(), n, &enc_buf[offset]);
            std::cout << "to client " << n << std::endl;
            reinterpret_cast<std::size_t *>(&enc_buf[0])[0] = n;
            client_stream.expires_after(timeout);
            async_write(client_stream, boost::asio::buffer(enc_buf, enc_buffer_size), yield[ec]);
            if (ec) {
                return;
            }
        }
    }

    void server_session::resolve_domain_name(const yield_context &yield, error_code ec) {
        std::string remote_host(client_buf.begin(), client_buf.begin() + client_message_length - 2);
        std::string remote_port = std::to_string(big_to_native(*((uint16_t *) &client_buf[client_message_length - 2])));
        tcp::resolver::query query(remote_host, remote_port);
        tcp::resolver::iterator endpoint_iterator = resolver.async_resolve(query, yield[ec]);
        if (ec) {
            std::cout << "Failed to resolve domain name" << std::endl;
            //TODO: Спросить про то, какой код выставить
            answer[1] = 0x03;
            return;
        }
        ep = *endpoint_iterator;
    }

    std::string server_session::socket_to_string(tcp::socket &socket, error_code ec) {
        tcp::endpoint endpoint = client_stream.socket().remote_endpoint(ec);
        if (ec) {
            return "closed socket";
        }
        return endpoint.address().to_string() + " " + std::to_string(big_to_native(endpoint.port()));

    }

    std::string server_session::endpoint_to_string() {
        return ep.address().to_string() + " " +
               std::to_string(big_to_native(ep.port()));
    }
}

