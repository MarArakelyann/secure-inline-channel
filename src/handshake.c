#include <stdio.h>
#include <openssl/evp.h>
#include "handshake.h"

int generate_keypair(
    EVP_PKEY **private_key,
    unsigned char public_key[DH_KEY_SIZE]
) {
    EVP_PKEY_CTX *context;
    size_t public_key_length = DH_KEY_SIZE;

    context = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    if (context == NULL) {
        return 0;
    }

    if (EVP_PKEY_keygen_init(context) <= 0) {
        EVP_PKEY_CTX_free(context);
        return 0;
    }

    if (EVP_PKEY_keygen(context, private_key) <= 0) {
        EVP_PKEY_CTX_free(context);
        return 0;
    }

    if (EVP_PKEY_get_raw_public_key(
            *private_key, public_key, &public_key_length) <= 0) {
        EVP_PKEY_free(*private_key);
        *private_key = NULL;
        EVP_PKEY_CTX_free(context);
        return 0;
    }

    EVP_PKEY_CTX_free(context);

    return 1;
}

int derive_shared_secret(
    EVP_PKEY *private_key,
    const unsigned char peer_public_key[DH_KEY_SIZE],
    unsigned char shared_secret[DH_KEY_SIZE]
) {
    EVP_PKEY *peer_key;
    EVP_PKEY_CTX *context;
    size_t secret_length = DH_KEY_SIZE;

    peer_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        NULL,
        peer_public_key,
        DH_KEY_SIZE
    );

    if (peer_key == NULL) {
        return 0;
    }

    context = EVP_PKEY_CTX_new(private_key, NULL);

    if (context == NULL) {
        EVP_PKEY_free(peer_key);
        return 0;
    }

    if (EVP_PKEY_derive_init(context) <= 0) {
        EVP_PKEY_CTX_free(context);
        EVP_PKEY_free(peer_key);
        return 0;
    }

    if (EVP_PKEY_derive_set_peer(context, peer_key) <= 0) {
        EVP_PKEY_CTX_free(context);
        EVP_PKEY_free(peer_key);
        return 0;
    }

    if (EVP_PKEY_derive(
            context, shared_secret, &secret_length) <= 0) {
        EVP_PKEY_CTX_free(context);
        EVP_PKEY_free(peer_key);
        return 0;
    }

    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(peer_key);

    return 1;
}
