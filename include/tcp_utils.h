#ifndef TCP_UTILS_H
#define TCP_UTILS_H

#include <stddef.h>
#include <stdint.h>

/**
 * Represents the standard TCP Header (20 bytes minimum).
 */
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

/**
 * Represents the IPv4 Pseudo-Header used for TCP Checksum calculation.
 * This header is never transmitted over the wire; it is only used mathematically
 * to verify that the packet reached the correct IP destination.
 */
struct pseudo_header {
    uint32_t source_ip;  // Source IP address (32 bits)
    uint32_t dest_ip;    // Destination IP address (32 bits)
    uint8_t reserved;    // Reserved (always set to 0)
    uint8_t protocol;    // Protocol type (6 for TCP)
    uint16_t tcp_length; // Length of TCP header + data (16 bits)
} __attribute__((packed));

/**
 * Calculates the standard Internet Checksum (RFC 1071).
 * * @param ptr    Pointer to the data buffer to be checksummed.
 * @param nbytes Number of bytes in the buffer.
 * @return       The 16-bit one's complement checksum.
 */
unsigned short calculate_checksum(unsigned short *ptr, int nbytes);

/**
 * Crafts and sends a generic TCP segment, optionally including a data payload.
 *
 * @param sock        The raw socket file descriptor.
 * @param src_ip      Source IP address as a string (e.g., "192.168.1.5").
 * @param dst_ip      Destination IP address as a string.
 * @param src_port    Source port number.
 * @param dst_port    Destination port number.
 * @param seq         Current Sequence Number for this packet.
 * @param ack         Acknowledgment Number (confirms received data).
 * @param flags       TCP Control flags. Standard values (Hex):
 * - 0x01: FIN (Finish/Close connection)
 * - 0x02: SYN (Synchronize/Start connection)
 * - 0x04: RST (Reset connection)
 * - 0x08: PSH (Push data payload)
 * - 0x10: ACK (Acknowledgment)
 * Combinations:
 * - 0x12: SYN-ACK (SYN | ACK)
 * - 0x18: PSH-ACK (PSH | ACK) - Use this when sending data!
 * - 0x11: FIN-ACK (FIN | ACK)
 * @param payload     Pointer to the data payload (NULL if no data).
 * @param payload_len Size of the payload in bytes (0 if no data).
 * @return            Number of bytes sent, or -1 on error.
 */
int send_tcp_segment(int sock, const char *src_ip, const char *dst_ip,
                     uint16_t src_port, uint16_t dst_port,
                     uint32_t seq, uint32_t ack, uint8_t flags,
                     const unsigned char *payload, size_t payload_len);

/**
 * Listens for incoming TCP segments and extracts control information and payload.
 * It automatically filters traffic to capture only packets addressed to our port.
 *
 * @param sock              The raw socket file descriptor.
 * @param expected_dst_port The local port we are listening on.
 * @param out_flags         Pointer to store the received TCP flags (e.g., 0x12 for SYN-ACK).
 * @param out_seq           Pointer to store the received Sequence Number.
 * @param out_ack           Pointer to store the received Acknowledgment Number.
 * @param out_payload       Buffer to store the extracted payload (must be pre-allocated).
 * @param out_payload_len   Pointer to store the actual size of the received payload.
 * @return                  0 on successful parse, or -1 on error.
 */
int receive_tcp_segment(int sock, uint16_t expected_dst_port,
                        uint8_t *out_flags, uint32_t *out_seq, uint32_t *out_ack,
                        unsigned char *out_payload, size_t *out_payload_len);

#endif // TCP_UTILS_H
