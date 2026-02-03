#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Represents the standard TCP Header (20 bytes minimum)
struct tcp_header {
    uint16_t source_port; // Source port (16 bits)
    uint16_t dest_port;   // Destination port (16 bits)
    uint32_t seq;         // Sequence number (32 bits)
    uint32_t ack;         // Acknowledgment number (32 bits)

    // Data Offset (4 bits), Reserved (4 bits), Flags (8 bits)
    // Note: To avoid endianness issues with bit-fields, we combine these.
    uint8_t data_offset_res; // High 4 bits: header length, Low 4 bits: reserved
    uint8_t flags;           // Control flags (FIN, SYN, RST, PSH, ACK, URG)

    uint16_t window;   // Window size (16 bits)
    uint16_t checksum; // Checksum for error-checking (16 bits)
    uint16_t urg_ptr;  // Urgent pointer (16 bits)
} __attribute__((packed));

// Represents the IPv4 Pseudo-Header used for TCP Checksum calculation
struct pseudo_header {
    uint32_t source_ip;  // Source IP address (32 bits)
    uint32_t dest_ip;    // Destination IP address (32 bits)
    uint8_t reserved;    // Reserved (always set to 0)
    uint8_t protocol;    // Protocol type (6 for TCP)
    uint16_t tcp_length; // Length of TCP header + data (16 bits)
} __attribute__((packed));

// Checksum =~ sum(Pseudo Header) + sum(TCP Header) + sum(Data)

unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    register long sum = 0;
    unsigned short oddbyte;
    register short answer;

    // 1. Sum up all 16-bit words
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    // 2. Add left-over byte, if any (pad to 16 bits)
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    // 3. Fold 32-bit sum to 16 bits
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    // 4. One's complement
    answer = (short)~sum;
    return answer;
}

int main() {
    // AF_INET: Address Family (IPv4 Address)
    // SOCK_RAW:
    // IPPROTO_TCP:
    // 1. Open the raw socket
    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (raw_socket < 0) {
        perror("❌ Failed to creare raw socket. Check CAT_NEW_RAW privileges");
        exit(EXIT_FAILURE);
    }

    printf("✅ Raw socket opened with file descriptor %d\n", raw_socket);

    // 2. Define target address (sockaddr_in)
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(80); // htons: Host TO Network Short
    inet_pton(AF_INET, "192.168.1.100", &target.sin_addr);

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
    inet_pton(AF_INET, "192.168.1.50", &psh.source_ip); // My fake IP
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
        perror("Failed to send packet");
    } else {
        printf("SYN Packet sent! Sent %d bytes.\n", sent_bytes);
    }

    free(pseudogram);

    close(raw_socket);

    return 0;
}
