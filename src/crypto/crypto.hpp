#ifndef SOCKS5_SERVER_CRYPTO_HPP
#define SOCKS5_SERVER_CRYPTO_HPP

#include <openssl/evp.h>
#include <iostream>
#include <vector>

namespace socks {

    class crypto {

    public:

        crypto(std::vector<uint8_t> key, std::vector<uint8_t> iv);

        std::vector<uint8_t> get_hmac(std::vector<uint8_t> message);

        bool verify_hmac(std::vector<uint8_t> message, std::vector<uint8_t> digest);

        int decrypt(unsigned char *cipher_text, int cipher_text_len, unsigned char *plain_text);

        int encrypt(unsigned char *plain_text, int plain_text_len, unsigned char *cipher_text);

    private:

        std::vector<uint8_t> key;
        std::vector<uint8_t> iv;

    };
}


#endif //SOCKS5_SERVER_CRYPTO_HPP
