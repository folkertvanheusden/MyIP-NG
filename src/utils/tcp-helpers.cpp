#include <cinttypes>
#include <cstdint>
#include <cstring>

#include "gen.h"
#include "log.h"
#include "shm.h"
#include "shm_message.h"
#include "tcp-helpers.h"


extern std::atomic_bool stop_flag;

int send_func(tcp_l7_session_t *const session, const uint8_t *const from, const size_t n)
{
	DOLOG(logger::ll_debug, "send %zu bytes", n);
	int rc = -1;

	shm_message_queue::message *data_msg = allocate_shm_message(12 + n);
	memcpy(&data_msg->data[0], &session->session_id, 8);
	uint32_t flags = 0;
	memcpy(&data_msg->data[8], &flags, 4);
	memcpy(&data_msg->data[12], from, n);

	if (session->shm_from_l7->put_message(data_msg) == false)
		DOLOG(logger::ll_warning, "Cannot send data via shm-from-l7");
	else
		rc = n;

	free(data_msg);

	return rc;
}

int recv_func(tcp_l7_session_t *const session, uint8_t *const to, const size_t n)
{
	DOLOG(logger::ll_debug, "get %zu bytes", n);
	if (n == 0)
		return 0;

	uint8_t *p    = to;
	size_t   todo = n;
	size_t   done = 0;
	while(todo > 0 && session->stop_flag == false && stop_flag == false) {
		auto   values = session->incoming.pop(SLEEP_INTERVAL_MS);
		if (values.has_value() == false)
			continue;
		size_t v_n    = values.value().size();
		memcpy(p, values.value().data(), std::min(todo, v_n));

		if (v_n > todo) {
			session->incoming.unpop(std::vector<uint8_t>(values.value().data() + todo, values.value().data() + v_n));
			done += todo;
			todo = 0;
		}
		else {
			todo -= v_n;
			p    += v_n;
			done += v_n;
		}
	}

	return done;
}

void fin_func(tcp_l7_session_t *const session)
{
	shm_message_queue::message *end_msg = allocate_shm_message(12);
	memcpy(&end_msg->data[0], &session->session_id, 8);
	uint32_t flags = MI_TCP_FIN;
	memcpy(&end_msg->data[8], &flags, 4);

	if (session->shm_from_l7->put_message(end_msg) == false)
		DOLOG(logger::ll_warning, "Cannot send FIN message");

	free(end_msg);
}

void receive_incoming_from_message_queue(shm_message_queue *const mq, queue<std::vector<uint8_t> > *const q_target)
{
	assert(mq);
	while(!stop_flag) {
		printf("hier001\n");
		shm_message_queue::message *m = mq->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_any, { });
		if (!m)
			continue;
		printf("daar\n");

		uint64_t       session_id   = 0;
                size_t         from_len     = 0;
		uint16_t       from_port    = 0;
                size_t         to_len       = 0;
		uint16_t       to_port      = 0;
                size_t         pl_len       = 0;
		uint32_t       flags        = 0;
                const uint8_t *from         = nullptr;
                const uint8_t *to           = nullptr;
                const uint8_t *pl           = nullptr;
		if (unwrap_message_to_tcp_l7(
				m,
				&session_id,
				&from_len, &from,
				&from_port,
				&to_len, &to,
				&to_port,
				&flags,
				&pl_len, &pl) == false) {
                        DOLOG(logger::ll_error, "ERR) Corrupt message in shared memory segment!");
                        free(m);
                        continue; 
		}

		DOLOG(logger::ll_debug, "Data for session %" PRIx64 "%s", session_id, flags & MI_TCP_FIN ? " +FIN": "");

		q_target->push(std::vector<uint8_t>(pl, &pl[pl_len]));

		free(m);
	}
}
