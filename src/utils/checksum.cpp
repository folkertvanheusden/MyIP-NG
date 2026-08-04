#include <cstdint>
#include <arpa/inet.h>


uint16_t ip_checksum(const uint16_t *const p, const size_t n)
{
        uint32_t cksum = 0;

        for(size_t i=0; i<n; i++) 
                cksum += htons(p[i]);

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += cksum >> 16;

        return ~cksum;
}
