#include <cstdint>

#include "addresses.h"


// n is number of uint16s
uint16_t ip_checksum(const uint16_t *const p, const size_t n);

// n is number of bytes in p
uint16_t tcp_udp_checksum(const addr_ip4 & from, const addr_ip4 & to, const uint8_t *const p, const size_t n, const uint8_t protocol_number);
