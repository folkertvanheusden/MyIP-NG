#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include "addresses.h"
#include "queue.h"


#define MI_TCP_FIN   1
#define MI_TCP_OPEN  2
#define MI_TCP_CLOSE 4
#define MI_IP4_MIN_TCP_MTU 536

struct tcp_l7_session_t
{
	const uint64_t     session_id;
	const std::string  out_name;
	shm_message_queue *const shm;
	const addr_ip4     from;
	const uint16_t     from_port;
	const addr_ip4     to;
	const uint16_t     to_port;

	std::atomic_bool   finished  { false };
	std::atomic_bool   stop_flag { false };
	queue<std::vector<uint8_t> > incoming;

	tcp_l7_session_t(const uint64_t session_id, const std::string & out_name,
		shm_message_queue *const shm,
		const addr_ip4 from, const uint16_t from_port,
		const addr_ip4 to,   const uint16_t to_port):
		session_id(session_id), out_name(out_name), shm(shm),
		from(from), from_port(from_port),
		to  (to  ), to_port  (to_port  )
	{
	}
};

int send_func(tcp_l7_session_t *const session, const uint8_t *const from, const size_t n);
int recv_func(tcp_l7_session_t *const session, uint8_t *const to, const size_t n);
void fin_func(tcp_l7_session_t *const session);
