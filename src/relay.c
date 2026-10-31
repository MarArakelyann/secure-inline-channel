#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>

#define LISTEN_PORT 55001
#define DEVICE2_IP "192.168.5.11"
#define DEVICE2_PORT 55000
#define BUFFER_SIZE 4096

int send_all(int socket_fd, char *buffer, int length) {
    int total_sent = 0;
    int bytes_sent;

    while (total_sent < length) {
        bytes_sent = send(socket_fd, buffer + total_sent,
                          length - total_sent, 0);

        if (bytes_sent <= 0) {
            return -1;
        }

        total_sent += bytes_sent;
    }

    return total_sent;
}

int main() {
    int server_socket;
    int client_socket;
    int device2_socket;
    int max_socket;
    int bytes_received;
    int activity;

    struct sockaddr_in server_address;
    struct sockaddr_in device2_address;

    fd_set read_fds;
    char buffer[BUFFER_SIZE];

    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (server_socket < 0) {
        perror("Socket creation failed");
        return 1;
    }

    memset(&server_address, 0, sizeof(server_address));

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(LISTEN_PORT);
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr *)&server_address,
             sizeof(server_address)) < 0) {
        perror("Bind failed");
        close(server_socket);
        return 1;
    }

    if (listen(server_socket, 1) < 0) {
        perror("Listen failed");
        close(server_socket);
        return 1;
    }

    printf("Relay: Waiting for Device 1...\n");

    client_socket = accept(server_socket, NULL, NULL);

    if (client_socket < 0) {
        perror("Accept failed");
        close(server_socket);
        return 1;
    }

    printf("Device 1 connected!\n");

    device2_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (device2_socket < 0) {
        perror("Device 2 socket failed");
        close(client_socket);
        close(server_socket);
        return 1;
    }

    memset(&device2_address, 0, sizeof(device2_address));

    device2_address.sin_family = AF_INET;
    device2_address.sin_port = htons(DEVICE2_PORT);

    if (inet_pton(AF_INET, DEVICE2_IP,
                  &device2_address.sin_addr) <= 0) {
        printf("Invalid Device 2 IP!\n");
        close(device2_socket);
        close(client_socket);
        close(server_socket);
        return 1;
    }

    if (connect(device2_socket,
                (struct sockaddr *)&device2_address,
                sizeof(device2_address)) < 0) {
        perror("Connection to Device 2 failed");
        close(device2_socket);
        close(client_socket);
        close(server_socket);
        return 1;
    }

    printf("Connected to Device 2!\n");
    printf("Bidirectional relay is ready!\n");

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(client_socket, &read_fds);
        FD_SET(device2_socket, &read_fds);

        max_socket = client_socket;

        if (device2_socket > max_socket) {
            max_socket = device2_socket;
        }

        activity = select(max_socket + 1, &read_fds,
                          NULL, NULL, NULL);

        if (activity < 0) {
            perror("Select failed");
            break;
        }

        if (FD_ISSET(client_socket, &read_fds)) {
            bytes_received = recv(client_socket, buffer,
                                  BUFFER_SIZE, 0);

            if (bytes_received <= 0) {
                break;
            }

            if (send_all(device2_socket, buffer,
                         bytes_received) < 0) {
                break;
            }

            printf("Device 1 -> Device 2: %d bytes\n",
                   bytes_received);
        }

        if (FD_ISSET(device2_socket, &read_fds)) {
            bytes_received = recv(device2_socket, buffer,
                                  BUFFER_SIZE, 0);

            if (bytes_received <= 0) {
                break;
            }

            if (send_all(client_socket, buffer,
                         bytes_received) < 0) {
                break;
            }

            printf("Device 2 -> Device 1: %d bytes\n",
                   bytes_received);
        }
    }

    close(device2_socket);
    close(client_socket);
    close(server_socket);

    printf("Relay stopped.\n");

    return 0;
}
