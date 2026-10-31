#ifndef CRYPTO_H
#define CRYPTO_H

#define KEY_SIZE 32
#define NONCE_SIZE 12
#define TAG_SIZE 16

int aes_gcm_encrypt(
    const unsigned char *key,
    const unsigned char *nonce,
    const unsigned char *plaintext,
    int plaintext_len,
    unsigned char *ciphertext,
    unsigned char *tag
);

int aes_gcm_decrypt(
    const unsigned char *key,
    const unsigned char *nonce,
    const unsigned char *ciphertext,
    int ciphertext_len,
    const unsigned char *tag,
    unsigned char *plaintext
);

#endif
