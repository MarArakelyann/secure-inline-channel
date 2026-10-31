#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/evp.h>

#include "crypto.h"
#include "handshake.h"
#include "kdf.h"

#define PORT 5000
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
    int server_socket;
    int client_socket;

    int option = 1;

    struct sockaddr_in server_address;

    EVP_PKEY *private_key = NULL;

    unsigned char public_key[DH_KEY_SIZE];
    unsigned char peer_public_key[DH_KEY_SIZE];

    unsigned char shared_secret[DH_KEY_SIZE];
    unsigned char aes_key[KDF_KEY_SIZE];

    unsigned char nonce[NONCE_SIZE];
    unsigned char tag[TAG_SIZE];

    unsigned char ciphertext[BUFFER_SIZE];
    unsigned char plaintext[BUFFER_SIZE + 1];

    uint32_t network_length;
    int ciphertext_length;
    int plaintext_length;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (server_socket < 0) {
        printf("Socket creation failed!\n");
        return 1;
    }

    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR,
               &option, sizeof(option));

    memset(&server_address, 0, sizeof(server_address));

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(PORT);

    if (bind(server_socket,
             (struct sockaddr *)&server_address,
             sizeof(server_address)) < 0) {
        printf("Binding failed!\n");
        close(server_socket);
        return 1;
    }

    if (listen(server_socket, 5) < 0) {
        printf("Listening failed!\n");
        close(server_socket);
        return 1;
    }

    printf("Device 2: Waiting for Device 1...\n");

    client_socket = accept(server_socket, NULL, NULL);

    if (client_socket < 0) {
        printf("Connection failed!\n");
        close(server_socket);
        return 1;
    }

    printf("Device 1 connected!\n");

    /* Receive Device 1's public key */

    if (!receive_all(client_socket, peer_public_key, DH_KEY_SIZE)) {
        printf("Public key receiving failed!\n");
        close(client_socket);
        close(server_socket);
        return 1;
    }

    /* Generate Device 2's X25519 key pair */

    if (!generate_keypair(&private_key, public_key)) {
        printf("Key generation failed!\n");
        close(client_socket);
        close(server_socket);
        return 1;
    }

    /* Send Device 2's public key */

    if (!send_all(client_socket, public_key, DH_KEY_SIZE)) {
        printf("Public key sending failed!\n");
        EVP_PKEY_free(private_key);
        close(client_socket);
        close(server_socket);
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
        close(server_socket);
        return 1;
    }

    /* Derive AES key using HKDF */

    if (!derive_aes_key(shared_secret, aes_key)) {
        printf("AES key derivation failed!\n");
        EVP_PKEY_free(private_key);
        close(client_socket);
        close(server_socket);
        return 1;
    }

    printf("Session key established!\n");

    /* Receive ciphertext length */

    if (!receive_all(client_socket,
                     (unsigned char *)&network_length,
                     sizeof(network_length))) {
        printf("Length receiving failed!\n");
        EVP_PKEY_free(private_key);
        close(client_socket);
        close(server_socket);
        return 1;
    }

    ciphertext_length = (int)ntohl(network_length);

    if (ciphertext_length <= 0 ||
        ciphertext_length > BUFFER_SIZE) {
        printf("Invalid ciphertext length!\n");
        EVP_PKEY_free(private_key);
        close(client_socket);
        close(server_socket);
        return 1;
    }

    /* Receive nonce, ciphertext, and authentication tag */

    if (!receive_all(client_socket, nonce, NONCE_SIZE) ||
        !receive_all(client_socket, ciphertext, ciphertext_length) ||
        !receive_all(client_socket, tag, TAG_SIZE)) {
        printf("Encrypted message receiving failed!\n");
        EVP_PKEY_free(private_key);
        close(client_socket);
        close(server_socket);
        return 1;
    }

    /* Decrypt and authenticate message */

    plaintext_length = aes_gcm_decrypt(
        aes_key,
        nonce,
        ciphertext,
        ciphertext_length,
        tag,
        plaintext
    );

    if (plaintext_length < 0) {
        printf("Authentication failed! Message rejected.\n");
    } else {
        plaintext[plaintext_length] = '\0';

        printf("Message authenticated and decrypted!\n");
        printf("Received message: %s\n", plaintext);
    }

    EVP_PKEY_free(private_key);
    close(client_socket);
    close(server_socket);

    return 0;
}
