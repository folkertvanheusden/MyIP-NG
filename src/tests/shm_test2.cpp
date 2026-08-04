#include <cassert>
#include <cstdint>

#include "../utils/log.h"
#include "../utils/shm.h"
#include "../utils/shm_message.h"


int main(int argc, char *argv[])
{
	log_.set_loglevel(logger::ll_debug);

	uint8_t from[] { 0x01, 0x02, 0x03, 0x04 };
	uint8_t to  [] { 0x05, 0x06             };
	uint8_t pl  [] { 0x07                   };

	shm_message_queue::message *m = wrap_message(sizeof from, from, sizeof to, to, sizeof pl, pl, { });

	size_t   s_from = 0;
	size_t   s_to   = 0;
	size_t   s_pl   = 0;
	const uint8_t *o_from = nullptr;
	const uint8_t *o_to   = nullptr;
	const uint8_t *o_pl   = nullptr;

	assert(unwrap_message(m, &s_from, &o_from, &s_to, &o_to, &s_pl, &o_pl));

	assert(s_from == sizeof(from));
	assert(s_to   == sizeof(to  ));
	assert(s_pl   == sizeof(pl  ));

	assert(memcmp(from, o_from, s_from) == 0);
	assert(memcmp(to  , o_to  , s_to  ) == 0);
	assert(memcmp(pl  , o_pl  , s_pl  ) == 0);

	return 0;
}
