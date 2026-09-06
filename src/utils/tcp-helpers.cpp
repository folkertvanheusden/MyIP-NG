#include <cstdint>
#include <cstring>

#include "gen.h"
#include "log.h"
#include "shm.h"
#include "../tcp.h"
#include "tcp-helpers.h"


extern std::atomic_bool stop_flag;

int send_func(tcp_l7_session_t *const session, const uint8_t *const from, const size_t n)
{
	int rc = -1;

	shm_message_queue::message *data_msg = allocate_shm_message(12 + n);
	memcpy(&data_msg->data[0], &session->session_id, 8);
	uint32_t flags = 0;
	memcpy(&data_msg->data[8], &flags, 4);
	memcpy(&data_msg->data[12], from, n);

	if (session->shm->send_message(session->out_name, data_msg, true) == false)
		DOLOG(logger::ll_warning, "Cannot send HTTP headers to %s", session->out_name.c_str());
	else
		rc = n;

	free(data_msg);

	return rc;
}

int recv_func(tcp_l7_session_t *const session, uint8_t *const to, const size_t n)
{
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

	if (session->shm->send_message(session->out_name, end_msg, true) == false)
		DOLOG(logger::ll_warning, "Cannot send FIN message to %s", session->out_name.c_str());

	free(end_msg);
}
