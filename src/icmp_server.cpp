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
#include "utils/time.h"


std::atomic_bool stop_flag { false };

void sig_handler(int sig)
{
	stop_flag = true;
}

// IP -> ICMP
void run_in(shm_message_queue *const shm, const std::string & out_name)
{
	while(!stop_flag) {
		shm_message_queue::message *m = shm->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_new, { });
		if (!m)
			continue;

		// unwrap
                size_t         full_pkt_len = 0;
                size_t         from_len     = 0;
                size_t         to_len       = 0;
                size_t         pl_len       = 0;
                const uint8_t *full_pkt     = nullptr;
                const uint8_t *from         = nullptr;
                const uint8_t *to           = nullptr;
                const uint8_t *pl           = nullptr;
                if (unwrap_message_up(m, &full_pkt_len, &full_pkt, &from_len, &from, &to_len, &to, &pl_len, &pl) == false) {
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
		uint16_t checksum = ip_checksum(reinterpret_cast<const uint16_t *>(pl), pl_len);
		if (checksum != 0x0000) {
			DOLOG(logger::ll_debug, "ICMP packet has incorrect checksum");
			free(m);
			continue;
		}

		if (type == 8 && code == 0) {  // echo request
			addr_ip4 from_ip4(from, from_len);

			std::string age_str;
			if (pl_len >= 24) {  // may include timestamp
				timeval tv { };
				memcpy(&tv, &pl[8], sizeof tv);

				uint64_t now_local = get_us();

				if (labs(tv.tv_sec - now_local / 1'000'000) < 3) {
					uint64_t age = now_local - (tv.tv_sec * 1'000'000 + tv.tv_usec);
					age_str += " (sent " + std::to_string(age) + " µs ago)";
				}
			}

			DOLOG(logger::ll_debug, "ECHO request from %s%s", from_ip4.to_str('.', false).c_str(), age_str.c_str());

			size_t   reply_len = pl_len;
			uint8_t *reply     = new uint8_t[reply_len];
			memcpy(reply, pl, reply_len);

			reply[0] = 0;  // echo reply
			reply[1] = 0;

			reply[2] = 0;
			reply[3] = 0;
			uint16_t checksum_reply = ip_checksum(reinterpret_cast<const uint16_t *>(reply), reply_len);
			reply[2] = checksum_reply >> 8;
			reply[3] = checksum_reply;

			auto *wrapped = wrap_message_down(
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

void run_err(shm_message_queue *const shm_err, const std::string & out_name, shm_message_queue *const shm_out)
{
	while(!stop_flag) {
		shm_message_queue::message *m_in = shm_err->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_new, { });
		if (!m_in)
			continue;

		// unwrap
                size_t         full_pkt_len = 0;
                size_t         from_len     = 0;
                size_t         to_len       = 0;
                size_t         pl_len       = 0;
                const uint8_t *full_pkt     = nullptr;
                const uint8_t *from         = nullptr;
                const uint8_t *to           = nullptr;
                const uint8_t *pl           = nullptr;
                if (unwrap_message_up(m_in, &full_pkt_len, &full_pkt, &from_len, &from, &to_len, &to, &pl_len, &pl) == false) {
			DOLOG(logger::ll_error, "Corrupt message in shared memory segment!");
			free(m_in);
			continue;
		}

		if (full_pkt_len < 20) {
			DOLOG(logger::ll_debug, "ICMP error handler: IP header too short? (%zu, from %s)", full_pkt_len, m_in->sender);
			free(m_in);
			continue;
		}

		int type = pl[0];
		int code = pl[1];

		DOLOG(logger::ll_debug, "Creating ICMP packet with type %d and code %d for %s", type, code, addr_ip4(to, to_len).to_str('.', false).c_str());

		size_t ip_header_size    = (pl[2] & 15) * 4;
		size_t copy_n            = std::min(full_pkt_len, ip_header_size + 64 / 8);
		size_t icmp_message_size = 8 + copy_n;
		uint8_t *m_out = new uint8_t[icmp_message_size]();
		m_out[0] = type;
		m_out[1] = code;
		memcpy(&m_out[8], &full_pkt[0], copy_n);

		uint16_t checksum_msg = ip_checksum(reinterpret_cast<const uint16_t *>(m_out), icmp_message_size);
		m_out[2] = checksum_msg >> 8;
		m_out[3] = checksum_msg;

		auto *wrapped = wrap_message_down(
				from_len,  from,
				to_len,    to,
				icmp_message_size, m_out,
				{ });

		if (shm_out->send_message(out_name, wrapped, false) == false)
			DOLOG(logger::ll_warning, "Cannot send to %s", out_name.c_str());

		free(wrapped);

		delete [] m_out;

		free(m_in);
	}
}

void run(shm_message_queue *const shm, const std::string & out_name, shm_message_queue *const shm_error)
{
	std::thread rx ([&] { run_in (shm,       out_name     ); });
	std::thread err([&] { run_err(shm_error, out_name, shm); });
	err.join();
	rx .join();
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
	std::string error_in_name = iniparser_getstring(d, "global:error-in-name",  "");
	if (error_in_name.empty()) {
		fprintf(stderr, "\"error-in-name\" under \"global\" missing\n");
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
		fprintf(stderr, "Cannot initialize shared memory segment \"%s\"\n", name.c_str());
		return 1;
	}

	shm_message_queue shm_error(error_in_name, msg_queue_size);
	if (shm_error.begin() == false) {
		fprintf(stderr, "Cannot initialize shared memory segment \"%s\"\n", error_in_name.c_str());
		return 1;
	}

	run(&shm, out_name, &shm_error);

	return 0;
}
