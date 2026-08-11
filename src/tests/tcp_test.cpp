#include <atomic>
#include <cassert>
#include <thread>
#include <unistd.h>

#include "../utils/log.h"
#include "../utils/shm.h"


int main(int argc, char *argv[])
{
#if defined(NDEBUG)
	printf("ASSERT IS DISABLED: NOT A DEBUG BUILD\n");
#endif
	constexpr const int         queue_size       = 16384;
	constexpr const char *const local_identifier = "local-tcp";

	shm_message_queue q_a(local_identifier, queue_size);
	bool rc = q_a.begin();
	assert(rc);

	std::string open_req = "action=open\ndst-port=80\ndst-addr-ip4=94.142.246.159";
        shm_message_queue::message *m_open_req = allocate_shm_message(open_req.size());
        m_open_req->type   = shm_message_queue::msg_new;
        memcpy(m_open_req->data, open_req.c_str(), m_open_req->size);
        bool rc_send = q_a.send_message(argv[1], m_open_req, true);
	assert(rc_send);
        free(m_open_req);

	return 0;
}
