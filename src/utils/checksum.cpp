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
	cksum += n * 2;

	for(size_t i=0; i<n; i++)
		cksum += htons(reinterpret_cast<const uint16_t *>(p)[i]);

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += cksum >> 16;

	return ~cksum;
}

uint64_t fletcher64(const uint8_t *const data, const size_t count)
{
	uint64_t sum1   = 0;
	uint64_t sum2   = 0;
	const uint32_t *data32 = reinterpret_cast<const uint32_t*>(data);
	const size_t    words  = count / 4;
	for(size_t i=0; i < words; i++) {
		sum1 = (sum1 + data32[i]) % UINT32_MAX;
		sum2 = (sum2 + sum1     ) % UINT32_MAX;
	}

	int extra = count & 3;
	if (extra) {
		size_t   offset = words * 4;
		uint32_t temp   = 0;
		for(int i=0; i<extra; i++)
			temp <<= 8, temp |= data[offset + i];

		sum1 = (sum1 + temp) % UINT32_MAX;
		sum2 = (sum2 + sum1) % UINT32_MAX;
	}

	return (sum2 << 32) | sum1;
}
