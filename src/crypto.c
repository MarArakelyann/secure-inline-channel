#include <stdio.h>
#include <openssl/evp.h>
#include "crypto.h"

int aes_gcm_encrypt(
    const unsigned char *key,
    const unsigned char *nonce,
    const unsigned char *plaintext,
    int plaintext_len,
    unsigned char *ciphertext,
    unsigned char *tag
) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        return 0;
    }

    if (EVP_EncryptInit_ex(
        ctx, EVP_aes_256_gcm(), NULL, NULL, NULL
    ) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (EVP_CIPHER_CTX_ctrl(
        ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL
    ) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (EVP_EncryptInit_ex(
        ctx, NULL, NULL, key, nonce
    ) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (EVP_EncryptUpdate(
        ctx, ciphertext, &len, plaintext, plaintext_len
    ) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(
        ctx, ciphertext + len, &len
    ) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(
        ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag
    ) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int aes_gcm_decrypt(
    const unsigned char *key,
    const unsigned char *nonce,
    const unsigned char *ciphertext,
    int ciphertext_len,
    const unsigned char *tag,
    unsigned char *plaintext
) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        return -1;
    }

    if (EVP_DecryptInit_ex(
        ctx, EVP_aes_256_gcm(), NULL, NULL, NULL
    ) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(
        ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL
    ) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptInit_ex(
        ctx, NULL, NULL, key, nonce
    ) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(
        ctx, plaintext, &len, ciphertext, ciphertext_len
    ) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(
        ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
        (void *)tag
    ) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptFinal_ex(
        ctx, plaintext + len, &len
    ) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
