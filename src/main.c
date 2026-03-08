#include "tcp_utils.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SRC_IP "172.16.241.1"
#define DST_IP "172.16.241.134"
#define SRC_PORT 12345
#define DST_PORT 80

// TCP Flags
#define TCP_SYN 0x02
#define TCP_ACK 0x10
#define TCP_SYN_ACK 0x12
#define TCP_PSH_ACK 0x18

int main() {
    // 1. Open the raw socket
    // AF_INET:     IPv4
    // SOCK_RAW:    Raw socket (we build our own TCP headers)
    // IPPROTO_TCP: Protocol is TCP
    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (raw_socket < 0) {
        perror("Failed to create raw socket. Run as root");
        exit(EXIT_FAILURE);
    }

    printf("[+] Raw socket created (fd: %d)\n", raw_socket);

    // 2. Prepare receive variables
    uint8_t recv_flags;
    uint32_t recv_seq, recv_ack;
    unsigned char recv_payload[4096];
    size_t recv_payload_len;

    // 3. Send SYN --> (Start the Three-Way Handshake)
    uint32_t our_isn = 1000; // Our Initial Sequence Number

    int sent = send_tcp_segment(raw_socket, SRC_IP, DST_IP,
                                SRC_PORT, DST_PORT,
                                our_isn, 0, TCP_SYN,
                                NULL, 0);

    if (sent < 0) {
        perror("Failed to send SYN");
        close(raw_socket);
        exit(EXIT_FAILURE);
    }

    printf("[+] SYN sent (seq=%u)\n", our_isn);

    // 4. Receive <-- SYN-ACK (Server responds)
    printf("[*] Waiting for SYN-ACK...\n");

    if (receive_tcp_segment(raw_socket, SRC_PORT,
                            &recv_flags, &recv_seq, &recv_ack,
                            recv_payload, &recv_payload_len) < 0) {
        fprintf(stderr, "Failed to receive SYN-ACK\n");
        close(raw_socket);
        exit(EXIT_FAILURE);
    }

    if (recv_flags != TCP_SYN_ACK) {
        fprintf(stderr, "Expected SYN-ACK (0x12), got 0x%02x\n", recv_flags);
        close(raw_socket);
        exit(EXIT_FAILURE);
    }

    uint32_t server_isn = recv_seq;
    printf("[+] SYN-ACK received (server_seq=%u, server_ack=%u)\n", server_isn, recv_ack);

    // 5. Send ACK --> (Complete the Three-Way Handshake)
    // Our seq advances by 1 (SYN consumes one sequence number)
    // We acknowledge the server's ISN + 1
    uint32_t our_seq = our_isn + 1;
    uint32_t our_ack = server_isn + 1;

    sent = send_tcp_segment(raw_socket, SRC_IP, DST_IP,
                            SRC_PORT, DST_PORT,
                            our_seq, our_ack, TCP_ACK,
                            NULL, 0);

    if (sent < 0) {
        perror("Failed to send ACK");
        close(raw_socket);
        exit(EXIT_FAILURE);
    }

    printf("[+] ACK sent (seq=%u, ack=%u) -- Handshake complete!\n", our_seq, our_ack);

    // 6. Send PSH-ACK --> with data (Transmit payload)
    const char *message = "Hello from xtcp!\n";
    size_t msg_len = strlen(message);

    sent = send_tcp_segment(raw_socket, SRC_IP, DST_IP,
                            SRC_PORT, DST_PORT,
                            our_seq, our_ack, TCP_PSH_ACK,
                            (const unsigned char *)message, msg_len);

    if (sent < 0) {
        perror("Failed to send data");
        close(raw_socket);
        exit(EXIT_FAILURE);
    }

    printf("[+] PSH-ACK sent with %zu bytes of data\n", msg_len);
    printf("[+] Payload: \"%s\"\n", message);

    // 7. Cleanup
    close(raw_socket);
    printf("[+] Socket closed. Done.\n");

    return 0;
}
