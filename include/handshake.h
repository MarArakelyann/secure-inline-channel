#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <openssl/evp.h>

#define DH_KEY_SIZE 32

int generate_keypair(
    EVP_PKEY **private_key,
    unsigned char public_key[DH_KEY_SIZE]
);

int derive_shared_secret(
    EVP_PKEY *private_key,
    const unsigned char peer_public_key[DH_KEY_SIZE],
    unsigned char shared_secret[DH_KEY_SIZE]
);

#endif
