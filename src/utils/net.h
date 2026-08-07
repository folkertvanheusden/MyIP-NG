#include <cstdint>

// network byte order
uint16_t get_uint16(const uint8_t from[2]);
uint32_t get_uint32(const uint8_t from[4]);

void put_uint16(uint8_t to[2], const uint16_t from);
void put_uint32(uint8_t to[4], const uint32_t from);
