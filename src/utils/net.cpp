#include <cstdint>


uint16_t get_uint16(const uint8_t from[2])
{
	return (from[0] << 8) | from[1];
}

uint32_t get_uint32(const uint8_t from[4])
{
	return (from[0] << 24) | (from[1] << 16) | (from[2] << 8) | from[3];
}

void put_uint16(uint8_t to[2], const uint16_t from)
{
	to[0] = from >> 8;
	to[1] = from;
}

void put_uint32(uint8_t to[4], const uint32_t from)
{
	to[0] = from >> 24;
	to[1] = from >> 16;
	to[2] = from >>  8;
	to[3] = from;
}
