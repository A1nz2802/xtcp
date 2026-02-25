#include "tcp_utils.h" // Including our custom headers
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main() {
    // AF_INET: Address Family (IPv4 Address)
    // SOCK_RAW: Raw socket for custom headers
    // IPPROTO_TCP: We are building TCP

    // 1. Open the raw socket
    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (raw_socket < 0) {
        perror("❌ Failed to create raw socket. Check root privileges");
        exit(EXIT_FAILURE);
    }

    printf("✅ Raw socket opened with file descriptor %d\n", raw_socket);

    // 2. Define target address (sockaddr_in)
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(80); // htons: Host TO Network Short
    inet_pton(AF_INET, "172.16.241.134", &target.sin_addr);

    // 3. Initialize TCP Header
    struct tcp_header tcph;
    memset(&tcph, 0, sizeof(struct tcp_header));

    tcph.source_port = htons(12345); // Random source port
    tcph.dest_port = htons(80);      // Target port
    tcph.seq = htonl(1000);          // Initial Sequence Number (ISN)
    tcph.ack = 0;                    // ACK is 0 for the first SYN packet

    // Data offset is 5 words (5 * 4 = 20 bytes). High 4 bits.
    tcph.data_offset_res = (5 << 4) | 0;

    // Set the SYN flag (Bit 2)
    tcph.flags = 0x02;

    tcph.window = htons(5840); // Maximum window size
    tcph.checksum = 0;         // Set to 0 before calculating
    tcph.urg_ptr = 0;

    // 4. Initialize Pseudo-header
    struct pseudo_header psh;
    inet_pton(AF_INET, "172.16.241.1", &psh.source_ip); // Host IP
    psh.dest_ip = target.sin_addr.s_addr;
    psh.reserved = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcp_header));

    // 5. Memory buffer for checksum calculation (Pseudo + TCP Header)
    int psh_size = sizeof(struct pseudo_header) + sizeof(struct tcp_header);
    unsigned char *pseudogram = malloc(psh_size);

    // Copy pseudo-header and tcp_header into the buffer
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), &tcph, sizeof(struct tcp_header));

    // 6. Calculate checksum and assign it
    tcph.checksum = calculate_checksum((unsigned short *)pseudogram, psh_size);

    // 7. Send the packet
    int sent_bytes = sendto(raw_socket, &tcph, sizeof(struct tcp_header), 0,
                            (struct sockaddr *)&target, sizeof(target));

    if (sent_bytes < 0) {
        perror("❌ Failed to send packet");
    } else {
        printf("🚀 SYN Packet sent! Sent %d bytes.\n", sent_bytes);
    }

    free(pseudogram);

    // 8. Prepare the receive buffer
    unsigned char recv_buffer[4096];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);

    printf("\n⏳ Waiting for server response (SYN-ACK)...\n");

    // Infinite loop: Catch packets until we find ours
    while (1) {
        // Receive raw packet (IP Header + TCP Header + Data)
        ssize_t data_size = recvfrom(raw_socket, recv_buffer, sizeof(recv_buffer), 0,
                                     (struct sockaddr *)&sender, &sender_len);

        if (data_size < 0) {
            perror("❌ Error in recvfrom");
            break;
        }

        // 9. Advance the pointer!
        // Skip the 20 bytes of the IP header to reach the TCP Header
        struct tcp_header *recv_tcph = (struct tcp_header *)(recv_buffer + 20);

        // --- 10. FILTER: The "Bouncer" of your program ---
        // Does it come from port 80 and go to our port 12345?
        if (recv_tcph->source_port == htons(80) && recv_tcph->dest_port == htons(12345)) {

            // Does it have exactly the SYN and ACK flags on? (0x12)
            // (In binary: 0001 0010 = 18 in decimal = 0x12 in Hex)
            if (recv_tcph->flags == 0x12) {
                printf("\n✅ SYN-ACK packet caught!\n");

                // 11. Extract the numbers (Endianness strikes back!)
                // We use ntohl() (Network TO Host Long) to convert the 32 bits to PC format
                uint32_t server_seq = ntohl(recv_tcph->seq);
                uint32_t server_ack = ntohl(recv_tcph->ack);

                printf("   -> Server Seq Number (Random): %u\n", server_seq);
                printf("   -> Server Ack Number (Your 1000 + 1): %u\n", server_ack);

                // Break the loop because we already have what we need
                break;
            }
        }
    }

    // Close the socket at the end of the execution
    close(raw_socket);

    return 0;
}
