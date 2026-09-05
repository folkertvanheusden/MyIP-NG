#include <cstdint>
#include <arpa/inet.h>

#include "addresses.h"


uint16_t ip_checksum(const uint16_t *const p, const size_t n)
{
	uint32_t cksum = 0;

        for(size_t i=0; i<n / 2; i++)
                cksum += htons(p[i]);
	if (n & 1)
		cksum += reinterpret_cast<const uint8_t *>(p)[n - 1] << 8;

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += cksum >> 16;

	return ~cksum;
}

uint16_t tcp_udp_checksum(const addr_ip4 & from, const addr_ip4 & to, const uint8_t *const p, const size_t n, const uint8_t protocol_number)
{
	uint32_t cksum = 0;

	const uint16_t *from16 = reinterpret_cast<const uint16_t *>(from.get());
	cksum += htons(from16[0]);
	cksum += htons(from16[1]);
	const uint16_t *to16   = reinterpret_cast<const uint16_t *>(to.get());
	cksum += htons(to16[0]);
	cksum += htons(to16[1]);
	cksum += protocol_number;
	cksum += n;

	for(size_t i=0; i<n / 2; i++)
		cksum += htons(reinterpret_cast<const uint16_t *>(p)[i]);
	if (n & 1)
		cksum += p[n - 1] << 8;

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += cksum >> 16;

	return ~cksum;
}
