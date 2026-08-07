#include <cassert>
#include <cstdint>

#include "../utils/addresses.h"
#include "../utils/checksum.h"


int main(int argc, char *argv[])
{
#if defined(NDEBUG)
	printf("ASSERT IS DISABLED: NOT A DEBUG BUILD\n");
#endif
	addr from("192.168.1.9", ".", false);
	addr to  ("10.208.0.10", ".", false);
	uint8_t test_data[] = "Dit is een test.";

	uint16_t checksum = tcp_udp_checksum(from, to, test_data, sizeof(test_data) / 2, 42);
	assert(checksum == 0x915b);

	return 0;
}
