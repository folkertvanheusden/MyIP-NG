#include <cstdint>
#include <arpa/inet.h>


uint16_t get_uint16(const uint8_t from[2])
{
	return ntohs(*reinterpret_cast<const uint16_t *>(from));
}

uint32_t get_uint32(const uint8_t from[4])
{
	return ntohl(*reinterpret_cast<const uint32_t *>(from));
}
