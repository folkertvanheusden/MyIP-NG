#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "addresses.h"
#include "queue.h"


#define MI_TCP_FIN   1  // TODO via meta channel?
#define MI_TCP_OPEN  2
#define MI_TCP_CLOSE 4
#define MI_IP4_MIN_TCP_MTU 536
#define TCP_WAIT_FIN 30'000  // ms

void receive_incoming_from_message_queue(shm_message_queue *const mq, queue<std::vector<uint8_t> > *const q_target);

struct tcp_l7_session_t
{
	const uint64_t     session_id;
	shm_message_queue *const shm_from_l7;
	shm_message_queue *const shm_to_l7;
	const addr_ip4     from;
	const uint16_t     from_port;
	const addr_ip4     to;
	const uint16_t     to_port;
	std::thread       *in_th { };

	std::atomic_bool   finished  { false };
	std::atomic_bool   stop_flag { false };
	queue<std::vector<uint8_t> > incoming;

	tcp_l7_session_t(const uint64_t session_id,
		shm_message_queue *const shm_from_l7,
		shm_message_queue *const shm_to_l7,
		const addr_ip4 from, const uint16_t from_port,
		const addr_ip4 to,   const uint16_t to_port):
		session_id(session_id),
		shm_from_l7(shm_from_l7), shm_to_l7(shm_to_l7),
		from(from), from_port(from_port),
		to  (to  ), to_port  (to_port  )
	{
		in_th = new std::thread([&] {
				DOLOG(logger::ll_debug, "tcp_l7_session_t incoming message handler running");
				receive_incoming_from_message_queue(this->shm_to_l7, &incoming);
			});
	}

	virtual ~tcp_l7_session_t()
	{
		stop_flag = true;
		in_th->join();
		delete in_th;
	}
};

int send_func(tcp_l7_session_t *const session, const uint8_t *const from, const size_t n);
int recv_func(tcp_l7_session_t *const session, uint8_t *const to, const size_t n);
void fin_func(tcp_l7_session_t *const session);
