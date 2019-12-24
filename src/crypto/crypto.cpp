#include "crypto.hpp"

namespace socks {

    crypto::crypto(std::vector<uint8_t> key, std::vector<uint8_t> iv)
            : key(std::move(key)),
              iv(std::move(iv)) {
    }

    int socks::crypto::decrypt(uint8_t *cipher_text, int cipher_text_len, uint8_t *plain_text) {
        EVP_CIPHER_CTX *ctx;
        int len;
        int plain_text_len;
        if (!(ctx = EVP_CIPHER_CTX_new())) {
            throw std::runtime_error("Failed to decrypt (new)\n");
        }
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
            throw std::runtime_error("Failed to decrypt (init)\n");
        }
        if (1 != EVP_DecryptUpdate(ctx, plain_text, &len, cipher_text, cipher_text_len)) {
            throw std::runtime_error("Failed to decrypt (update)\n");
        }
        plain_text_len = len;
        if (1 != EVP_DecryptFinal_ex(ctx, plain_text + len, &len)) {
            throw std::runtime_error("Failed to decrypt (final)\n");
        }
        plain_text_len += len;
        EVP_CIPHER_CTX_free(ctx);
        return plain_text_len;
    }

    int socks::crypto::encrypt(uint8_t *plain_text, int plain_text_len, uint8_t *cipher_text) {
        EVP_CIPHER_CTX *ctx;
        int len;
        int cipher_text_len;
        if (!(ctx = EVP_CIPHER_CTX_new())) {
            throw std::runtime_error("Failed to encrypt\n");
        }
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
            throw std::runtime_error("Failed to encrypt\n");
        }
        if (1 != EVP_EncryptUpdate(ctx, cipher_text, &len, plain_text, plain_text_len)) {
            throw std::runtime_error("Failed to encrypt\n");
        }
        cipher_text_len = len;
        if (1 != EVP_EncryptFinal_ex(ctx, cipher_text + len, &len)) {
            throw std::runtime_error("Failed to encrypt\n");
        }
        cipher_text_len += len;
        EVP_CIPHER_CTX_free(ctx);
        return cipher_text_len;
    }

    std::vector<uint8_t> crypto::get_hmac(uint8_t *message, int message_length) {
        uint8_t hash[32];
        HMAC_CTX hmac;
        HMAC_CTX_init(&hmac);
        HMAC_Init_ex(&hmac, &key[0], key.size(), EVP_sha256(), nullptr);
        HMAC_Update(&hmac, message, message_length);
        unsigned int len = 32;
        HMAC_Final(&hmac, hash, &len);
        HMAC_CTX_cleanup(&hmac);
        return std::vector<uint8_t>(hash, hash + 32);
    }

    bool crypto::verify_hmac(uint8_t *message, int message_length, uint8_t *digest) {
        std::vector<uint8_t> hmac = get_hmac(message, message_length);
        return hmac == std::vector<uint8_t>(digest, digest + 32);
    }
}
