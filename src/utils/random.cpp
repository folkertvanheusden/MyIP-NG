#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/random.h>

#include "log.h"


void my_random(void *const target, const size_t n_bytes)
{
	if (getrandom(target, n_bytes, 0) == -1) {
		DOLOG(logger::ll_fatal, "getrandom failed: %s", strerror(errno));
		exit(1);
	}
}
