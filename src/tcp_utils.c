#include "tcp_utils.h"

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
