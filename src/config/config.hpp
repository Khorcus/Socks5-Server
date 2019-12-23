#ifndef SOCKS5_SERVER_CONFIG_HPP
#define SOCKS5_SERVER_CONFIG_HPP

#include <iostream>
#include <utility>


struct server_config {
    server_config(std::size_t buffer_size, std::size_t timeout, std::vector<uint8_t> secret_key,
                  std::vector<uint8_t> iv, uint16_t local_port)
            : buffer_size(buffer_size),
              timeout(timeout),
              secret_key(std::move(secret_key)),
              server_port(local_port),
              iv(std::move(iv)) {
    }

    std::size_t buffer_size;
    std::chrono::seconds timeout;
    std::vector<uint8_t> secret_key;
    std::vector<uint8_t> iv;
    uint16_t server_port;
};

struct client_config : public server_config {
    client_config(
            std::size_t buffer_size, std::size_t timeout, std::vector<uint8_t> secret_key, std::vector<uint8_t> iv,
            uint16_t server_port, std::string server_ip, uint16_t client_port)
            : server_config(buffer_size, timeout, std::move(secret_key), std::move(iv), server_port),
              server_ip(std::move(server_ip)), client_port(client_port) {
    }

    std::string server_ip;
    uint16_t client_port;
};

#endif //SOCKS5_SERVER_CONFIG_HPP
