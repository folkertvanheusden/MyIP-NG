#include <cstdint>

uint16_t get_uint16(const uint8_t from[2])
{
	return ntohs(*reinterpret_cast<uint16_t>(from));
}

uint32_t get_uint32(const uint8_t from[4])
{
	return ntohl(*reinterpret_cast<uint32_t>(from));
}
