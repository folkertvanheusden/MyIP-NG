#include <cstdint>
#include <time.h>

#include "log.h"


uint64_t get_us()
{
	timespec ts { };
	if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
		DOLOG(logger::ll_error, "clock_gettime failed: %s", strerror(errno));
		return 0;
	}

	return ts.tv_sec * 1'000'000l + ts.tv_nsec / 1000;
}
