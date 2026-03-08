#include "tcp_utils.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

// Checksum =~ sum(Pseudo Header) + sum(TCP Header) + sum(Data)
// https://datatracker.ietf.org/doc/html/rfc1071
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

int send_tcp_segment(int sock, const char *src_ip, const char *dst_ip,
                     uint16_t src_port, uint16_t dst_port,
                     uint32_t seq, uint32_t ack, uint8_t flags,
                     const unsigned char *payload, size_t payload_len) {

    // 1. Define destination address (sockaddr_in)
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(dst_port); // htons: Host TO Network Short
    inet_pton(AF_INET, dst_ip, &target.sin_addr);

    // 2. Setup TCP Header
    struct tcp_header tcph;
    memset(&tcph, 0, sizeof(struct tcp_header));

    tcph.source_port = htons(src_port); // Source Port
    tcph.dest_port = htons(dst_port);   // Destination Port
    tcph.seq = htonl(seq);              // Initial Sequence Number (ISN)
    tcph.ack = htonl(ack);              // ACK is 0 for the first SYN packet

    // Data offset is 5 words (5 * 4 = 20 bytes). 20 bytes Standard TCP header, no options.
    tcph.data_offset_res = (5 << 4) | 0;
    tcph.flags = flags;
    tcph.window = htons(5840);
    tcph.checksum = 0; // Set to 0 before calculating
    tcph.urg_ptr = 0;

    // 3. Setup Pseudo-Header
    struct pseudo_header psh;
    inet_pton(AF_INET, src_ip, &psh.source_ip);
    psh.dest_ip = target.sin_addr.s_addr;
    psh.reserved = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcp_header) + payload_len); // [TCP] + [Payload]

    // 4. Prepare memory block for Checksum Calculation: [Pseudo] + [TCP] + [Payload]
    int psh_size = sizeof(struct pseudo_header) + sizeof(struct tcp_header) + payload_len;
    unsigned char *pseudogram = malloc(psh_size);

    // Copy pseudo-header, TCP header, and payload into the buffer for checksum calculation
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), &tcph, sizeof(struct tcp_header));

    if (payload != NULL && payload_len > 0) {
        memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcp_header), payload, payload_len);
    }

    // Calculate and assign the final checksum
    tcph.checksum = calculate_checksum((unsigned short *)pseudogram, psh_size);
    free(pseudogram);

    // 5. Prepare the actual packet to send: [TCP] + [Payload] (No Pseudo-header on the wire)
    int packet_size = sizeof(struct tcp_header) + payload_len;
    unsigned char *packet = malloc(packet_size);

    memcpy(packet, &tcph, sizeof(struct tcp_header));
    if (payload != NULL && payload_len > 0) {
        memcpy(packet + sizeof(struct tcp_header), payload, payload_len);
    }

    // 6. Send it to the network
    int sent_bytes = sendto(sock, packet, packet_size, 0,
                            (struct sockaddr *)&target, sizeof(target));

    free(packet);
    return sent_bytes;
}

int receive_tcp_segment(int sock, uint16_t expected_dst_port,
                        uint8_t *out_flags, uint32_t *out_seq, uint32_t *out_ack,
                        unsigned char *out_payload, size_t *out_payload_len) {

    // 1. Prepare the receive buffer
    unsigned char recv_buffer[4096];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);

    while (1) {
        // 2. Listen for incoming raw packets (blocks until one arrives)
        ssize_t data_size = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0,
                                     (struct sockaddr *)&sender, &sender_len);

        if (data_size < 0) {
            perror("Error in recvfrom");
            return -1;
        }

        // 3. Skip IP Header to reach TCP Header (pointer arithmetic)
        // Raw socket receives: [IP Header (20 bytes)] [TCP Header] [Payload]
        struct tcp_header *recv_tcph = (struct tcp_header *)(recv_buffer + 20);

        // 4. Filter: only accept packets addressed to our port
        if (recv_tcph->dest_port == htons(expected_dst_port)) {

            // 5. Extract control information (flags, seq, ack)
            *out_flags = recv_tcph->flags;
            *out_seq = ntohl(recv_tcph->seq);
            *out_ack = ntohl(recv_tcph->ack);

            // 6. Calculate payload boundaries
            // High 4 bits of data_offset_res = header length in 32-bit words (x4 bytes)
            int tcp_header_length = (recv_tcph->data_offset_res >> 4) * 4;
            int total_headers_size = 20 + tcp_header_length; // IP (20) + TCP (varies, usually 20)
            int payload_size = data_size - total_headers_size;

            // 7. Extract payload data
            if (payload_size > 0 && out_payload != NULL) {
                memcpy(out_payload, recv_buffer + total_headers_size, payload_size);
                *out_payload_len = payload_size;
                out_payload[payload_size] = '\0'; // Null-terminate for safe printing
            } else {
                *out_payload_len = 0;
            }

            return 0;
        }
    }
}
