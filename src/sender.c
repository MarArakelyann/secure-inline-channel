#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include "crypto.h"
#include "handshake.h"
#include "kdf.h"

#define PORT 55001
#define BUFFER_SIZE 1024

int send_all(int socket, const unsigned char *data, int length) {
    int total_sent = 0;
    int bytes_sent;

    while (total_sent < length) {
        bytes_sent = send(socket, data + total_sent,
                          length - total_sent, 0);

        if (bytes_sent <= 0) {
            return 0;
        }

        total_sent += bytes_sent;
    }

    return 1;
}

int receive_all(int socket, unsigned char *data, int length) {
    int total_received = 0;
    int bytes_received;

    while (total_received < length) {
        bytes_received = recv(socket, data + total_received,
                              length - total_received, 0);

        if (bytes_received <= 0) {
            return 0;
        }

        total_received += bytes_received;
    }

    return 1;
}

int main() {
    int client_socket;
    struct sockaddr_in server_address;

    EVP_PKEY *private_key = NULL;

    unsigned char public_key[DH_KEY_SIZE];
    unsigned char peer_public_key[DH_KEY_SIZE];

    unsigned char shared_secret[DH_KEY_SIZE];
    unsigned char aes_key[KDF_KEY_SIZE];

    unsigned char nonce[NONCE_SIZE];
    unsigned char tag[TAG_SIZE];

    unsigned char ciphertext[BUFFER_SIZE];

    char message[] = "Hello from Device 1 to Device 2!";

    int message_length;
    int ciphertext_length;
    uint32_t network_length;

    client_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (client_socket < 0) {
        printf("Socket creation failed!\n");
        return 1;
    }

    memset(&server_address, 0, sizeof(server_address));

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);

    inet_pton(AF_INET, "127.0.0.1",
              &server_address.sin_addr);

    if (connect(client_socket,
                (struct sockaddr *)&server_address,
                sizeof(server_address)) < 0) {
        printf("Connection failed!\n");
        close(client_socket);
        return 1;
    }

    printf("Device 1: Connected to Device 2!\n");

    /* Generate Device 1's X25519 key pair */

    if (!generate_keypair(&private_key, public_key)) {
        printf("Key generation failed!\n");
        close(client_socket);
        return 1;
    }

    /* Send Device 1's public key */

    if (!send_all(client_socket, public_key, DH_KEY_SIZE)) {
        printf("Public key sending failed!\n");
        EVP_PKEY_free(private_key);
        close(client_socket);
        return 1;
    }

    /* Receive Device 2's public key */

    if (!receive_all(client_socket, peer_public_key, DH_KEY_SIZE)) {
        printf("Public key receiving failed!\n");
        EVP_PKEY_free(private_key);
        close(client_socket);
        return 1;
    }

    printf("Public keys exchanged!\n");

    /* Derive shared secret */

    if (!derive_shared_secret(private_key,
                              peer_public_key,
                              shared_secret)) {
        printf("Shared secret derivation failed!\n");
        EVP_PKEY_free(private_key);
        close(client_socket);
        return 1;
    }

    /* Derive AES key using HKDF */

    if (!derive_aes_key(shared_secret, aes_key)) {
        printf("AES key derivation failed!\n");
        EVP_PKEY_free(private_key);
        close(client_socket);
        return 1;
    }

    printf("Session key established!\n");

    /* Generate a random AES-GCM nonce */

    if (RAND_bytes(nonce, NONCE_SIZE) != 1) {
        printf("Nonce generation failed!\n");
        EVP_PKEY_free(private_key);
        close(client_socket);
        return 1;
    }

    /* Encrypt message */

    message_length = strlen(message);

    ciphertext_length = aes_gcm_encrypt(
        aes_key,
        nonce,
        (unsigned char *)message,
        message_length,
        ciphertext,
        tag
    );

    if (ciphertext_length < 0) {
        printf("Encryption failed!\n");
        EVP_PKEY_free(private_key);
        close(client_socket);
        return 1;
    }


    /* Send ciphertext length */

    network_length = htonl((uint32_t)ciphertext_length);

    if (!send_all(client_socket,
                  (unsigned char *)&network_length,
                  sizeof(network_length))) {
        printf("Length sending failed!\n");
        EVP_PKEY_free(private_key);
        close(client_socket);
        return 1;
    }

    /* Send nonce, ciphertext, and authentication tag */

    if (!send_all(client_socket, nonce, NONCE_SIZE) ||
        !send_all(client_socket, ciphertext, ciphertext_length) ||
        !send_all(client_socket, tag, TAG_SIZE)) {
        printf("Encrypted message sending failed!\n");
        EVP_PKEY_free(private_key);
        close(client_socket);
        return 1;
    }

    printf("Encrypted message sent successfully!\n");

    EVP_PKEY_free(private_key);
    close(client_socket);

    return 0;
}
