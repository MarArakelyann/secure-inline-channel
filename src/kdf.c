#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "kdf.h"

int derive_aes_key(
    const unsigned char *shared_secret,
    unsigned char *aes_key
) {
    EVP_PKEY_CTX *context;
    size_t key_length = KDF_KEY_SIZE;

    context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (context == NULL) {
        return 0;
    }

    if (EVP_PKEY_derive_init(context) <= 0) {
        EVP_PKEY_CTX_free(context);
        return 0;
    }

    /* Use SHA-256 as the hash function */
    if (EVP_PKEY_CTX_set_hkdf_md(
            context, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(context);
        return 0;
    }

    /* Set the Diffie-Hellman shared secret as input key material */
    if (EVP_PKEY_CTX_set1_hkdf_key(
            context, shared_secret, KDF_KEY_SIZE) <= 0) {
        EVP_PKEY_CTX_free(context);
        return 0;
    }

    /* Identify the purpose of the derived key */
    const unsigned char info[] = "SecureInlineChannel AES-256-GCM key v1";

    if (EVP_PKEY_CTX_add1_hkdf_info(
            context, info, sizeof(info) - 1) <= 0) {
        EVP_PKEY_CTX_free(context);
        return 0;
    }

    /* Derive the 256-bit AES key */
    if (EVP_PKEY_derive(
            context, aes_key, &key_length) <= 0) {
        EVP_PKEY_CTX_free(context);
        return 0;
    }

    EVP_PKEY_CTX_free(context);

    return 1;
}
