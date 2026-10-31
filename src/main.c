#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "crypto.h"
#include "handshake.h"
#include "kdf.h"

int main() {
    EVP_PKEY *device1_private = NULL;
    EVP_PKEY *device2_private = NULL;

    unsigned char device1_public[DH_KEY_SIZE];
    unsigned char device2_public[DH_KEY_SIZE];

    unsigned char device1_secret[DH_KEY_SIZE];
    unsigned char device2_secret[DH_KEY_SIZE];

    unsigned char device1_aes_key[KDF_KEY_SIZE];
    unsigned char device2_aes_key[KDF_KEY_SIZE];

    unsigned char nonce[NONCE_SIZE];
    unsigned char tag[TAG_SIZE];

    unsigned char plaintext[] = "Hello from Device 1 to Device 2!";
    unsigned char ciphertext[256];
    unsigned char decrypted[256];

    int ciphertext_len;
    int decrypted_len;

    printf("=== Secure Inline Channel Test ===\n\n");

    /* STEP 1: Generate key pairs */

    printf("Step 1: Generating key pairs...\n");

    if (generate_keypair(&device1_private, device1_public) == 0) {
        printf("Device 1 key generation failed!\n");
        return 1;
    }

    if (generate_keypair(&device2_private, device2_public) == 0) {
        printf("Device 2 key generation failed!\n");
        EVP_PKEY_free(device1_private);
        return 1;
    }

    printf("Both devices generated their key pairs.\n");

    /* STEP 2: Exchange public keys and calculate shared secrets */

    printf("\nStep 2: Performing Diffie-Hellman exchange...\n");

    if (derive_shared_secret(
            device1_private, device2_public, device1_secret) == 0) {
        printf("Device 1 secret derivation failed!\n");
        EVP_PKEY_free(device1_private);
        EVP_PKEY_free(device2_private);
        return 1;
    }

    if (derive_shared_secret(
            device2_private, device1_public, device2_secret) == 0) {
        printf("Device 2 secret derivation failed!\n");
        EVP_PKEY_free(device1_private);
        EVP_PKEY_free(device2_private);
        return 1;
    }

    printf("Shared secrets established.\n");

    /* STEP 3: Derive AES keys using HKDF */

    printf("\nStep 3: Deriving AES keys with HKDF...\n");

    if (derive_aes_key(device1_secret, device1_aes_key) == 0 ||
        derive_aes_key(device2_secret, device2_aes_key) == 0) {
        printf("AES key derivation failed!\n");
        EVP_PKEY_free(device1_private);
        EVP_PKEY_free(device2_private);
        return 1;
    }

    if (memcmp(device1_aes_key, device2_aes_key, KDF_KEY_SIZE) != 0) {
        printf("AES keys do not match!\n");
        EVP_PKEY_free(device1_private);
        EVP_PKEY_free(device2_private);
        return 1;
    }

    printf("Both devices have the same AES key.\n");

    /* STEP 4: Generate a nonce */

    printf("\nStep 4: Generating AES-GCM nonce...\n");

    if (RAND_bytes(nonce, NONCE_SIZE) != 1) {
        printf("Nonce generation failed!\n");
        EVP_PKEY_free(device1_private);
        EVP_PKEY_free(device2_private);
        return 1;
    }

    printf("Nonce generated.\n");

    /* STEP 5: Device 1 encrypts the message */

    printf("\nStep 5: Device 1 encrypts the message...\n");

    ciphertext_len = aes_gcm_encrypt(
        device1_aes_key,
        nonce,
        plaintext,
        strlen((char *)plaintext),
        ciphertext,
        tag
    );

    if (ciphertext_len < 0) {
        printf("Encryption failed!\n");
        EVP_PKEY_free(device1_private);
        EVP_PKEY_free(device2_private);
        return 1;
    }

    printf("Encryption successful.\n");
    printf("Encrypted message length: %d bytes\n", ciphertext_len);

    /* STEP 6: Device 2 decrypts the message */

    printf("\nStep 6: Device 2 decrypts the message...\n");

    decrypted_len = aes_gcm_decrypt(
        device2_aes_key,
        nonce,
        ciphertext,
        ciphertext_len,
        tag,
        decrypted
    );

    if (decrypted_len < 0) {
        printf("Decryption failed: authentication error!\n");
        EVP_PKEY_free(device1_private);
        EVP_PKEY_free(device2_private);
        return 1;
    }

    decrypted[decrypted_len] = '\0';

    printf("Decryption successful.\n");
    printf("Decrypted message: %s\n", decrypted);

    /* STEP 7: Clean up */

    EVP_PKEY_free(device1_private);
    EVP_PKEY_free(device2_private);

    printf("\n=== Secure Communication Test Completed ===\n");

    return 0;
}

