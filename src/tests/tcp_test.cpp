#include <atomic>
#include <cassert>
#include <cinttypes>
#include <thread>
#include <unistd.h>

#include "../utils/gen.h"
#include "../utils/log.h"
#include "../utils/shm.h"


void emit(const std::string & channel, const shm_message_queue::message *const m)
{
	printf("channel: %s\n", channel.c_str());
	printf("msg nr : %" PRIu64 "\n", m->msg_nr);
	printf("type   : ");
	if (m->type == shm_message_queue::msg_new)
		printf("new\n");
	else if (m->type == shm_message_queue::msg_reply)
		printf("reply\n");
	else if (m->type == shm_message_queue::msg_any)
		printf("any\n");
	else
		printf("??? %d\n", m->type);
	printf("length : %u\n", m->size);
	printf("sender : %s\n", m->sender);
	printf("content: %s\n", std::string(reinterpret_cast<const char *>(m->data), m->size).c_str());
	printf("\n");
}

int main(int argc, char *argv[])
{
#if defined(NDEBUG)
	printf("ASSERT IS DISABLED: NOT A DEBUG BUILD\n");
#endif
	if (argc != 3) {
		fprintf(stderr, "%s tcp-meta tcp-upper\n", argv[0]);
		return 1;
	}

	constexpr const int         queue_size_meta       = 16384;
	constexpr const char *const local_identifier_meta = "local-meta-tcp";

	shm_message_queue q_a(local_identifier_meta, queue_size_meta);
	bool rc_a = q_a.begin();
	assert(rc_a);

	constexpr const int         queue_size_pl       = 16384;
	constexpr const char *const local_identifier_pl = "local-pl-tcp";

	shm_message_queue q_b(local_identifier_pl, queue_size_pl);
	bool rc_b = q_b.begin();
	assert(rc_b);

//	std::string open_req = "action=open\ndst-port=25\ndst-addr-ip4=94.142.246.159\nshm-data-address=local-pl-tcp";
	std::string open_req = "action=open\ndst-port=2500\ndst-addr-ip4=192.168.1.1\nshm-data-address=local-pl-tcp";
        shm_message_queue::message *m_open_req = allocate_shm_message(open_req.size());
        m_open_req->type   = shm_message_queue::msg_new;
        memcpy(m_open_req->data, open_req.c_str(), m_open_req->size);
        bool rc_send = q_a.send_message(argv[1], m_open_req, true);
	assert(rc_send);
        free(m_open_req);

	uint64_t session_id = 0;
	int      i          = 0;
	int      nr         = 0;

	for(;;) {
		shm_message_queue::message *m_a = q_a.wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_any, { });
		if (m_a) {
			emit("meta", m_a);

			std::string msg(reinterpret_cast<const char *>(m_a->data), m_a->size);
			if (msg.substr(0, 11) == "session-id=")
				session_id = std::strtoull(msg.substr(11).c_str(), nullptr, 16);
		}
		free(m_a);

		shm_message_queue::message *m_b = q_b.wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_any, { });
		if (m_b) {
			emit("pl", m_b);
			i = 0;
		}
		free(m_b);

		if (++i == 10) {
			printf("-> send 2nd message\n\n");

			std::string msg = "Hello back! " + std::to_string(++nr) + "\n";
			size_t       total_bytes  = 8 + msg.size();
			uint8_t     *complete_msg = new uint8_t[total_bytes];
			memcpy(&complete_msg[0], &session_id, sizeof session_id);
			memcpy(&complete_msg[8], msg.c_str(), msg.size());

			shm_message_queue::message *m_msg = allocate_shm_message(total_bytes);
			m_msg->type   = shm_message_queue::msg_new;
			memcpy(m_msg->data, complete_msg, total_bytes);
			bool rc_send = q_b.send_message(argv[2], m_msg, true);
			assert(rc_send);
			free(m_msg);

			delete [] complete_msg;
		}
	}

	return 0;
}
