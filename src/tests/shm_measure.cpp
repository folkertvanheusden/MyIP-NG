#include <atomic>
#include <cassert>
#include <cinttypes>
#include <cmath>
#include <numeric>
#include <thread>
#include <unistd.h>
#include <vector>

#include "../utils/log.h"
#include "../utils/shm.h"


const std::string identifier_a = "1234-test-a";

uint64_t get_us()
{
	timespec ts { };
	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec * 1'000'000 + ts.tv_nsec / 1000;
}

int main(int argc, char *argv[])
{
#if defined(NDEBUG)
	printf("ASSERT IS DISABLED: NOT A DEBUG BUILD\n");
#endif
	if (argc != 2) {
		fprintf(stderr, "Usage: %s count\n", argv[0]);
		return 1;
	}

	constexpr const int queue_size = sizeof(uint64_t) + 128;

	log_.set_loglevel(logger::ll_fatal);

	shm_message_queue q_a(identifier_a, queue_size);
	bool rc = q_a.begin();
	assert(rc);

	int                  count = std::stoi(argv[1]);
	std::vector<int64_t> samples;
	samples.resize(count);

	if ((count & 1) == 0) {
		fprintf(stderr, "Count must be odd\n");
		return 1;
	}

	std::thread t1([&q_a, count, &samples] {
			for(int i=0; i<count; i++) {
				auto    *p       = q_a.wait_for_message(1000, shm_message_queue::msg_any, { });
				if (!p)
					continue;
				auto     now     = get_us();
				uint64_t sent_at = *reinterpret_cast<const uint64_t *>(p->data);
				samples[i] = now - sent_at;
				free(p);
			}
		});

	std::thread t2([count] {
			shm_message_queue q_b(identifier_a, queue_size);
			bool rc = q_b.begin();
			assert(rc);

			shm_message_queue::message *m = allocate_shm_message(sizeof(uint64_t));

			for(int i=0; i<count; i++) {
				m->size = sizeof(uint64_t);
				m->type = shm_message_queue::msg_new;
				*reinterpret_cast<uint64_t *>(m->data) = get_us();
				bool rc_send = q_b.send_message(identifier_a, m, true);
				assert(rc_send);
				usleep(3);  // hopefully enough for the handling in the other thread
			}

			delete [] m;
		});

	t2.join();
	t1.join();

	std::sort(samples.begin(), samples.end());

	int64_t sum = std::accumulate(samples.begin(), samples.end(), 0);

	int64_t sd_sum = 0;
	for(auto & v: samples)
		sd_sum += v * v;

	double avg = sum / double(count);

	printf("Shortest: %" PRId64 " μs\n", samples[0]);
	printf("Longest : %" PRId64 " μs\n", samples[count - 1]);
	printf("Average : %.2f μs, standard deviation: %.2f μs\n", avg, sqrt(sd_sum / count - avg * avg));
	printf("Median  : %" PRId64 " μs\n", samples[count / 2]);

	return 0;
}
