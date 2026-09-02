#include <atomic>
#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <map>
#include <thread>
#include <arpa/inet.h>
#include <iniparser/iniparser.h>

#include "common.h"
#include "utils/addresses.h"
#include "utils/gen.h"
#include "utils/log.h"
#include "utils/net.h"
#include "utils/shm.h"
#include "utils/shm_message.h"


#define NTP_EPOCH (86400U * (365U * 70U + 17U))

struct sntp_datagram
{
        unsigned char mode : 3;
        unsigned char vn : 3;
        unsigned char li : 2;
        /* data */
        unsigned char stratum;
        char poll;
        char precision;
        u_int32_t root_delay;
        u_int32_t root_dispersion;
        u_int32_t reference_identifier;
        u_int32_t reference_timestamp_secs;
        u_int32_t reference_timestamp_fraq;
        u_int32_t originate_timestamp_secs;
        u_int32_t originate_timestamp_fraq;
        u_int32_t receive_timestamp_seqs;
        u_int32_t receive_timestamp_fraq;
        u_int32_t transmit_timestamp_secs;
        u_int32_t transmit_timestamp_fraq;
};

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

		if (pl_len < 4 + 48) {
			free(m);
			DOLOG(logger::ll_debug, "NTP packet too small");
			continue;
		}

		const sntp_datagram *sntp = reinterpret_cast<const sntp_datagram *>(&pl[4]);

		if (sntp->mode == 3) { // time request
			uint16_t source_port      = get_uint16(&pl[0]);
			uint16_t destination_port = get_uint16(&pl[2]);

			DOLOG(logger::ll_debug, "NTP time request from [%s]:%d",
				addr_ip4(from, from_len).to_str('.', false).c_str(), source_port);

			sntp_datagram msgout { 0 };

			msgout.li              = 0;
			msgout.mode            = 4; // 4: server
			msgout.vn              = 3;
			msgout.precision       = -18; // 3.8us
			msgout.stratum         = 1;
			msgout.root_delay      = 369098752; // not known
			msgout.root_dispersion = 369098752; // not known
			msgout.poll            = 16;
			memcpy(&msgout.reference_identifier, "LOCL", 4);

			msgout.originate_timestamp_secs = sntp->transmit_timestamp_secs;
			msgout.originate_timestamp_fraq = sntp->transmit_timestamp_fraq;

			timespec recv_now { };
			if (clock_gettime(CLOCK_REALTIME, &recv_now) == -1)
				DOLOG(logger::ll_error, "clock_gettime failed: %s", strerror(errno));

			msgout.receive_timestamp_seqs = htonl(recv_now.tv_sec + NTP_EPOCH);
			msgout.receive_timestamp_fraq = htonl(recv_now.tv_nsec / 1000 * 4295);

			auto now = recv_now;

			msgout.reference_timestamp_secs = htonl(now.tv_sec + NTP_EPOCH);
			msgout.reference_timestamp_fraq = htonl(now.tv_nsec / 1000 * 4295);

			msgout.transmit_timestamp_secs = htonl(now.tv_sec + NTP_EPOCH);
			msgout.transmit_timestamp_fraq = htonl(now.tv_nsec / 1000 * 4295);

			size_t   udp_message_size = 4 + sizeof msgout;
			uint8_t *m_out            = new uint8_t[udp_message_size];
			put_uint16(&m_out[0], destination_port);  // swapped as it is a reply
			put_uint16(&m_out[2], source_port     );
			memcpy(&m_out[4], &msgout, sizeof msgout);

			auto *wrapped = wrap_message_down(
					to_len,           to,  // swapped as it is as reply
					from_len,         from,
					udp_message_size, m_out,
					{ });

			if (shm->send_message(out_name, wrapped, false) == false)
				DOLOG(logger::ll_warning, "Cannot send to %s", out_name.c_str());

			free(wrapped);

			delete [] m_out;
		}
		else {
			DOLOG(logger::ll_debug, "Unknown NTP request ignored (%d)", sntp->mode);
		}

		free(m);
	}
}

void run(shm_message_queue *const shm, const std::string & out_name)
{
	std::thread rx([&] { run_in(shm, out_name); });
	rx.join();
}

int main(int argc, char *argv[])
{
	std::string cfg_file;
	int         c        = -1;
	while((c = getopt(argc, argv, "c:l:")) != -1) {
		if (c == 'c')
			cfg_file = optarg;
		else if (c == 'l')
			log_.set_loglevel(optarg);
	}

	if (cfg_file.empty()) {
		fprintf(stderr, "Use -c to select a configuration file\n");
		return 1;
	}

	DOLOG(logger::ll_info, "NTP server starting...");

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

	shm_message_queue *shm = create_shm(name, msg_queue_size);
	if (shm == nullptr)
		return 1;

	run(shm, out_name);

	delete shm;

	return 0;
}
