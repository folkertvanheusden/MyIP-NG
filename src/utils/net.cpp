#include <cstdint>


uint16_t get_uint16(const uint8_t from[2])
{
	return (from[0] << 8) | from[1];
}

uint32_t get_uint32(const uint8_t from[4])
{
	return (from[0] << 24) | (from[1] << 16) | (from[2] << 8) | from[3];
}
