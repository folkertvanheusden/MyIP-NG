#include <atomic>
#include <cassert>
#include <thread>
#include <unistd.h>

#include "../utils/log.h"
#include "../utils/shm.h"


const std::string identifier_a = "1234-test-a";
const std::string identifier_b = "5678-test-b";

int main(int argc, char *argv[])
{
	constexpr const int queue_size = 16384;

	log_.set_loglevel(logger::ll_fatal);

	shm_message_queue q_a(identifier_a, queue_size);
	bool rc = q_a.begin();
	assert(rc);

	std::atomic_uint64_t total_recv    = 0;
	std::atomic_uint64_t total_recv_ok = 0;

	std::thread t1([&q_a, &total_recv, &total_recv_ok] {
			printf("Thread 1 started\n");
			for(;;) {
				auto *p = reinterpret_cast<uint8_t *>(q_a.wait_for_message(10, shm_message_queue::msg_type(rand() % 3), { }));
				total_recv++;
				total_recv_ok += !!p;
				free(p);
			}
		});

	std::atomic_uint64_t total_sent    = 0;
	std::atomic_uint64_t total_sent_ok = 0;

	std::thread t2([&total_sent, &total_sent_ok] {
			shm_message_queue q_b(identifier_a, queue_size);
			bool rc = q_b.begin();
			assert(rc);

			printf("Thread 2 started\n");
			shm_message_queue::message *m = reinterpret_cast<shm_message_queue::message *>(new
					uint8_t[queue_size - sizeof(shm_message_queue::shared_memory)]());

			for(;;) {
				m->size = 1 + (rand() % (queue_size / 8));
				m->type = rand() & 1 ? shm_message_queue::msg_new : shm_message_queue::msg_reply;
				bool rc_send = q_b.send_message(identifier_a, m, true);
				total_sent++;
				total_sent_ok += rc_send;
			}

			delete [] m;
		});

	for(;;) {
		printf("%lu %lu | %lu %lu\n", long(total_recv), long(total_recv_ok), long(total_sent), long(total_sent_ok));
		sleep(1);
	}

	t2.join();
	t1.join();

	return 0;
}
