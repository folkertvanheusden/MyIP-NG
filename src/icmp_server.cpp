#include <atomic>
#include <cassert>
#include <cerrno>
#include <csignal>
#include <thread>
#include <iniparser/iniparser.h>

#include "utils/addresses.h"
#include "utils/checksum.h"
#include "utils/gen.h"
#include "utils/log.h"
#include "utils/net.h"
#include "utils/shm.h"
#include "utils/shm_message.h"
#include "utils/str.h"


std::atomic_bool stop_flag { false };

void sig_handler(int sig)
{
	stop_flag = true;
}

void run_in(shm_message_queue *const shm, const std::string & out_name)
{
	while(!stop_flag) {
		shm_message_queue::message *m = shm->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_new, { });
		if (!m)
			continue;

		// unwrap
		size_t         from_len = 0;
		size_t         to_len   = 0;
		size_t         pl_len   = 0;
		const uint8_t *from     = nullptr;
		const uint8_t *to       = nullptr;
		const uint8_t *pl       = nullptr;
		if (unwrap_message(m, &from_len, &from, &to_len, &to, &pl_len, &pl) == false) {
			DOLOG(logger::ll_error, "Corrupt message in shared memory segment!");
			free(m);
			continue;
		}

		if (pl_len < 8) {
			free(m);
			continue;
		}

		int type = pl[0];
		int code = pl[1];

		// check checksum
		uint16_t checksum = ip_checksum(reinterpret_cast<const uint16_t *>(pl), pl_len / 2);
		if (checksum != 0x0000) {
			DOLOG(logger::ll_debug, "ICMP packet has incorrect checksum");
			free(m);
			continue;
		}

		if (type == 8 && code == 0) {  // echo request
			addr_ip4 from_ip4(from, from_len);
			DOLOG(logger::ll_debug, "ECHO request from %s", from_ip4.to_str('.', false).c_str());

			size_t   reply_len = pl_len;
			uint8_t *reply     = new uint8_t[reply_len];
			memcpy(reply, pl, reply_len);

			reply[0] = 0;  // echo reply
			reply[1] = 0;

			reply[2] = 0;
			reply[3] = 0;
			uint16_t checksum_reply = ip_checksum(reinterpret_cast<const uint16_t *>(reply), reply_len / 2);
			reply[2] = checksum_reply >> 8;
			reply[3] = checksum_reply;

			auto *wrapped = wrap_message(
					to_len,    to,  // this is a reply, that's why they're swapped
					from_len,  from,
					reply_len, reply,
					{ });

			if (shm->send_message(out_name, wrapped, false) == false)
				DOLOG(logger::ll_warning, "Cannot send to %s", out_name.c_str());

			delete [] reply;

			free(wrapped);
		}

		free(m);
	}
}

void run(shm_message_queue *const shm, const std::string & out_name)
{
	std::thread rx ([&] { run_in (shm, out_name); });
	rx.join();
}

int main(int argc, char *argv[])
{
	std::string cfg_file;
	int         c        = -1;
	while((c = getopt(argc, argv, "c:")) != -1) {
		if (c == 'c')
			cfg_file = optarg;
	}

	if (cfg_file.empty()) {
		fprintf(stderr, "Use -c to select a configuration file\n");
		return 1;
	}

	DOLOG(logger::ll_info, "ICMP server starting...");

	dictionary *d = iniparser_load(cfg_file.c_str());
	for(int i=0; i<iniparser_getnsec(d); i++) {
		std::string section_name = iniparser_getsecname(d, i);
		if (section_name != "global" && section_name != "specific") {
			fprintf(stderr, "Section \"%s\" in configuration file is unknown\n", section_name.c_str());
			return 1;
		}
	}
	std::string name = iniparser_getstring(d, "global:lower-in-name",  "");
	if (name.empty()) {
		fprintf(stderr, "\"lower-in-name\" under \"global\" missing\n");
		return 1;
	}
	std::string out_name = iniparser_getstring(d, "global:out-name",  "");
	if (out_name.empty()) {
		fprintf(stderr, "\"out-name\" under \"global\" missing\n");
		return 1;
	}
	int msg_queue_size = iniparser_getint(d, "specific:msg-queue-size", 0);
	if (msg_queue_size == 0) {
		msg_queue_size = 16384;
		fprintf(stderr, "Using default msg queue size of %d bytes\n", msg_queue_size);
	}
	iniparser_freedict(d);

	signal(SIGINT, sig_handler);

	shm_message_queue shm(name, msg_queue_size);
	if (shm.begin() == false) {
		fprintf(stderr, "Cannot initialize shared memory segment\n");
		return 1;
	}

	run(&shm, out_name);

	return 0;
}
