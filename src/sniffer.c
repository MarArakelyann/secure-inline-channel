#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>

void packet_handler(
    unsigned char *user_data,
    const struct pcap_pkthdr *header,
    const unsigned char *packet
) {
    (void)user_data;

    if (header->caplen < 34) {
        return;
    }

    /* Check Ethernet type: IPv4 */
    if (packet[12] != 0x08 || packet[13] != 0x00) {
        return;
    }

    /* Locate the IP header */
    int ip_header_length = (packet[14] & 0x0F) * 4;

    if (ip_header_length < 20) {
        return;
    }

    if (header->caplen < 14 + ip_header_length) {
        return;
    }

    /* Check that the packet contains TCP */
    if (packet[23] != 6) {
        return;
    }

    /* Locate the TCP header */
    int tcp_offset = 14 + ip_header_length;

    if (header->caplen < tcp_offset + 20) {
        return;
    }

    int tcp_header_length =
        ((packet[tcp_offset + 12] >> 4) & 0x0F) * 4;

    if (tcp_header_length < 20 ||
        header->caplen < tcp_offset + tcp_header_length) {
        return;
    }

    /* Read IP addresses */
    char source_ip[INET_ADDRSTRLEN];
    char destination_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, packet + 26,
              source_ip, sizeof(source_ip));

    inet_ntop(AF_INET, packet + 30,
              destination_ip, sizeof(destination_ip));

    /* Read TCP ports */
    uint16_t source_port;
    uint16_t destination_port;

    memcpy(&source_port, packet + tcp_offset, 2);
    memcpy(&destination_port, packet + tcp_offset + 2, 2);

    source_port = ntohs(source_port);
    destination_port = ntohs(destination_port);

    /* Calculate TCP payload length */
    int ip_total_length =
        (packet[16] << 8) | packet[17];

    int payload_length =
        ip_total_length - ip_header_length - tcp_header_length;

    printf("\n--- TCP Packet ---\n");
    printf("Source IP: %s\n", source_ip);
    printf("Destination IP: %s\n", destination_ip);
    printf("Source port: %u\n", source_port);
    printf("Destination port: %u\n", destination_port);
    printf("TCP payload length: %d bytes\n", payload_length);
    printf("Captured frame size: %u bytes\n", header->len);
}

int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap_t *handle;

    handle = pcap_open_live(
        "eth1",
        BUFSIZ,
        0,
        1000,
        error_buffer
    );

    if (handle == NULL) {
        printf("Capture error: %s\n", error_buffer);
        return 1;
    }

    printf("Analyzing IPv4 TCP packets on eth1...\n");
    printf("Press Ctrl+C to stop.\n");

    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);

    return 0;
}


