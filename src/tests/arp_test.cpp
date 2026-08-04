#include <atomic>
#include <cassert>
#include <thread>
#include <unistd.h>

#include "../utils/log.h"
#include "../utils/shm.h"


int main(int argc, char *argv[])
{
	if (argc != 4) {
		fprintf(stderr, "Usage: %s local-name arp-request-name ip-addr\n", argv[0]);
		return 1;
	}

	constexpr const int queue_size = 16384;

	// init shm
	shm_message_queue shm(argv[1], queue_size);
	bool rc_init = shm.begin();
	assert(rc_init);

	// send request
        const std::string msg = std::format("search-mac={0}", argv[3]);
        shm_message_queue::message *res_req_msg = allocate_shm_message(msg.size());
        res_req_msg->type = shm_message_queue::msg_new;
        res_req_msg->size = msg.size();
        memcpy(res_req_msg->data, msg.c_str(), msg.size());
        bool rc_send = shm.send_message(argv[2], res_req_msg, true);
	assert(rc_send);

	// wait for reply
	auto *reply_msg = shm.wait_for_message(1000, shm_message_queue::msg_reply, { });
	if (reply_msg) {
		std::string reply_str = std::string(reinterpret_cast<const char *>(reply_msg->data), reply_msg->size);
		printf("Reply: %s\n", reply_str.c_str());
		free(reply_msg);
	}
	else {
		printf("No reply\n");
	}

	return 0;
}
