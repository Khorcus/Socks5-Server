#ifndef SOCKS5_SERVER_CRYPTO_HPP
#define SOCKS5_SERVER_CRYPTO_HPP

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <iostream>
#include <vector>

namespace socks {

    class crypto {

    public:

        const std::size_t CIPHER_BLOCK_SIZE = 16;
        const std::size_t DIGEST_SIZE = 32;

        crypto(std::vector<uint8_t> key, std::vector<uint8_t> iv);

        std::vector<uint8_t> get_hmac(uint8_t *message, int message_length);

        bool verify_hmac(uint8_t *message, int message_length, uint8_t *digest);

        int decrypt(uint8_t *cipher_text, int cipher_text_len, uint8_t *plain_text);

        int encrypt(uint8_t *plain_text, int plain_text_len, uint8_t *cipher_text);

    private:

        std::vector<uint8_t> key;
        std::vector<uint8_t> iv;

    };
}


#endif //SOCKS5_SERVER_CRYPTO_HPP
