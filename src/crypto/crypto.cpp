#include "crypto.hpp"

namespace socks {

    crypto::crypto(std::vector<uint8_t> key, std::vector<uint8_t> iv)
            : key(std::move(key)),
              iv(std::move(iv)) {
    }

    int socks::crypto::decrypt(unsigned char *cipher_text, int cipher_text_len, unsigned char *plain_text)
    {
        EVP_CIPHER_CTX *ctx;
        int len;
        int plain_text_len;
        if(!(ctx = EVP_CIPHER_CTX_new())){
            throw std::runtime_error("Failed to decrypt\n");
        }
        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
            throw std::runtime_error("Failed to decrypt\n");
        }
        if(1 != EVP_DecryptUpdate(ctx, plain_text, &len, cipher_text, cipher_text_len)) {
            throw std::runtime_error("Failed to decrypt\n");
        }
        plain_text_len = len;
        if(1 != EVP_DecryptFinal_ex(ctx, plain_text + len, &len)) {
            throw std::runtime_error("Failed to decrypt\n");
        }
        plain_text_len += len;
        EVP_CIPHER_CTX_free(ctx);
        return plain_text_len;
    }

    int socks::crypto::encrypt(unsigned char *plain_text, int plain_text_len, unsigned char *cipher_text)
    {
        EVP_CIPHER_CTX *ctx;
        int len;
        int cipher_text_len;
        if(!(ctx = EVP_CIPHER_CTX_new())) {
            throw std::runtime_error("Failed to encrypt\n");
        }
        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
            throw std::runtime_error("Failed to encrypt\n");
        }
        if(1 != EVP_EncryptUpdate(ctx, cipher_text, &len, plain_text, plain_text_len)) {
            throw std::runtime_error("Failed to encrypt\n");
        }
        cipher_text_len = len;
        if(1 != EVP_EncryptFinal_ex(ctx, cipher_text + len, &len)) {
            throw std::runtime_error("Failed to encrypt\n");
        }
        cipher_text_len += len;
        EVP_CIPHER_CTX_free(ctx);
        return cipher_text_len;
    }
}
