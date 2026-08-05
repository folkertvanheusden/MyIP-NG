#include <cstdint>
#include <arpa/inet.h>

#include "addresses.h"


uint16_t ip_checksum(const uint16_t *const p, const size_t n)
{
        uint32_t cksum = 0;

        for(size_t i=0; i<n; i++) 
                cksum += htons(p[i]);

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += cksum >> 16;

        return ~cksum;
}

// TODO optimize me
uint16_t tcp_udp_checksum(const addr_ip4 & from, const addr_ip4 & to, const uint8_t *const p, const size_t n, const uint8_t protocol_number)
{
	uint8_t *temp = new uint8_t[12 + n * 2]();

	memcpy(&temp[0], from.get(), 4);
	memcpy(&temp[4], to  .get(), 4);
	temp[9]  = protocol_number;
	temp[10] = n >> 8;
	temp[11] = n;
	memcpy(&temp[12], p, n);

        uint32_t cksum = 0;
        for(size_t i=0; i<n + 12 / 2; i++) 
                cksum += htons(reinterpret_cast<const uint16_t *>(temp)[i]);
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += cksum >> 16;

	free(temp);

        return ~cksum;
}
