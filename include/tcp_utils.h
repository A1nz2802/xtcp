#ifndef TCP_UTILS_H
#define TCP_UTILS_H

#include <stdint.h>

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

// Function prototype for the checksum calculator
unsigned short calculate_checksum(unsigned short *ptr, int nbytes);

#endif // TCP_UTILS_H
