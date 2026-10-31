#ifndef KDF_H
#define KDF_H

#define KDF_KEY_SIZE 32

int derive_aes_key(
    const unsigned char *shared_secret,
    unsigned char *aes_key
);

#endif
