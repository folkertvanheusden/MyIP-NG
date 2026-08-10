#include <cassert>
#include <cinttypes>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "../utils/shm.h"


#define PAD8(x)  (((x) & 7) ? (x) + 8 - ((x) & 7) : (x))

int main(int argc, char *argv[])
{
	int get_segment = shm_open(argv[1], O_RDONLY, 0600);
	if (get_segment == -1) {
		printf("shm_open failed: %s\n", strerror(errno));
		return 1;
	}

	struct stat segment_stat { };
	if (fstat(get_segment, &segment_stat) == -1) {
		printf("fstat failed: %s\n", strerror(errno));
		return 1;
	}

	shm_message_queue::shared_memory *get_shm = reinterpret_cast<shm_message_queue::shared_memory *>(mmap(nullptr, segment_stat.st_size, PROT_READ, MAP_SHARED, get_segment, 0));
	if (get_shm == MAP_FAILED) {
		printf("mmap failed: %s\n", strerror(errno));
		return 1;
	}

	uint8_t *end = &get_shm->data[get_shm->filled];
	uint8_t *cur = &get_shm->data[0];
	while(end - cur >= long(sizeof(shm_message_queue::message))) {
		shm_message_queue::message *m = reinterpret_cast<shm_message_queue::message *>(cur);
		uint32_t length       = m->size;
		size_t   total_length = PAD8(sizeof(shm_message_queue::message) + length);
		uint64_t cur_msg_nr   = m->msg_nr;
		assert(length > 0);

		printf("msg nr : %" PRIu64 "\n", cur_msg_nr);
		printf("type   : ");
		if (m->type == shm_message_queue::msg_new)
			printf("new\n");
		else if (m->type == shm_message_queue::msg_reply)
			printf("reply\n");
		else if (m->type == shm_message_queue::msg_any)
			printf("any\n");
		else
			printf("??? %d\n", m->type);
		printf("length : %u\n", length);
		printf("sender : %s\n", m->sender);
		printf("content: %s\n", std::string(reinterpret_cast<const char *>(m->data), m->size).c_str());
		printf("\n");

		cur += total_length;
		assert((long(cur) & 7) == 0);
	}

	return 0;
}
