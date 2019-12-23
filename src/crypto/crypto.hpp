#ifndef SOCKS5_SERVER_CRYPTO_HPP
#define SOCKS5_SERVER_CRYPTO_HPP

//#include <openssl/evp.h>
#include <iostream>

namespace socks {

    class crypto {

        std::vector<uint8_t> get_hmac(std::vector<uint8_t> message);

        bool verify_hmac(std::vector<uint8_t> message, std::vector<uint8_t> digest);

    };
}


#endif //SOCKS5_SERVER_CRYPTO_HPP
