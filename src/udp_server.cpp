#include <atomic>
#include <cassert>
#include <cerrno>
#include <csignal>
#include <map>
#include <thread>
#include <iniparser/iniparser.h>

#include "utils/addresses.h"
#include "utils/checksum.h"
#include "utils/gen.h"
#include "utils/log.h"
#include "utils/net.h"
#include "utils/shm.h"
#include "utils/shm_message.h"


std::atomic_bool stop_flag { false };

void sig_handler(int sig)
{
	stop_flag = true;
}

void run_in(shm_message_queue *const shm, const std::map<uint16_t, std::string> & mappings_in)
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
			DOLOG(logger::ll_debug, "UDP packet too small");
			continue;
		}
		uint16_t length = get_uint16(&pl[4]);
		if (length > pl_len) {
			free(m);
			DOLOG(logger::ll_debug, "UDP packet payload truncated (%d > %zu)", length, pl_len);
			continue;
		}

		// check checksum
		uint16_t checksum = tcp_udp_checksum(addr_ip4(from, from_len), addr_ip4(to, to_len), pl, pl_len, 17);
		if (checksum != 0x0000) {
			DOLOG(logger::ll_debug, "UDP packet has incorrect checksum");
			free(m);
			continue;
		}

		uint16_t source_port      = get_uint16(&pl[0]);
		uint16_t destination_port = get_uint16(&pl[2]);
		auto     it               = mappings_in.find(destination_port);
		if (it == mappings_in.end()) {
			DOLOG(logger::ll_debug, "No mapping for %d", destination_port);
			// TODO send ICMP 3, 3
			free(m);
			continue;
		}

		DOLOG(logger::ll_debug, "UDP packet from %d to %d", source_port, destination_port);

                size_t   udp_message_size = 4 + length;
                uint8_t *m_out            = new uint8_t[udp_message_size];
		memcpy(m_out, pl, 4);  // copy source & destination port
                memcpy(&m_out[4], &pl[8], length);

                auto *wrapped = wrap_message(
                                from_len,         from,
                                to_len,           to,
                                udp_message_size, m_out,
                                { });

                if (shm->send_message(it->second, wrapped, false) == false)
                        DOLOG(logger::ll_warning, "Cannot send to %s", it->second.c_str());

                free(wrapped);

                delete [] m_out;

		free(m);
	}
}

void run_out(shm_message_queue *const shm, const std::string & out_name)
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

		addr_ip4 a_from(from, from_len);
		addr_ip4 a_to  (to,   to_len);

		DOLOG(logger::ll_debug, "Creating UDP packet from [%s]:%d to [%s]:%d",
				a_from.to_str('.', false).c_str(), get_uint16(&pl[0]),
				a_to  .to_str('.', false).c_str(), get_uint16(&pl[2]));

		size_t   udp_packet_len = 8 + pl_len;
		uint8_t *udp_packet     = new uint8_t[udp_packet_len];
		memcpy(udp_packet, &pl[0], 4);
		udp_packet[4] = udp_packet_len >> 8;
		udp_packet[5] = udp_packet_len;
		udp_packet[6] = 0;
		udp_packet[7] = 0;
		memcpy(&udp_packet[8], &pl[4], pl_len - 4);
		uint16_t checksum = tcp_udp_checksum(addr_ip4(from, from_len), addr_ip4(to, to_len), udp_packet, udp_packet_len, 17);
		udp_packet[6] = checksum >> 8;
		udp_packet[7] = checksum;

                auto *wrapped = wrap_message(
                                from_len,       from,
                                to_len,         to,
                                udp_packet_len, udp_packet,
                                { });

                if (shm->send_message(out_name, wrapped, false) == false)
                        DOLOG(logger::ll_warning, "Cannot send to %s", out_name.c_str());

                free(wrapped);

		delete [] udp_packet;

		free(m);
	}
}


void run(shm_message_queue *const shm, const std::string & out_name,
	 const std::map<uint16_t, std::string> & mappings_in)
{
	std::thread rx([&] { run_in (shm, mappings_in); });
	std::thread tx([&] { run_out(shm, out_name   ); });  // TODO
	tx.join();
	rx.join();
}

void load_mappings(std::map<uint16_t, std::string> *const mappings_in, const dictionary *const d)
{
	constexpr const char section_name[] = "mappings";
	int n_keys = iniparser_getsecnkeys(d, section_name);
	if (n_keys == 0)
		return;
	const char **keys = new const char *[n_keys]();
	iniparser_getseckeys(d, section_name, keys);

	for(int i=0; i<n_keys; i++) {
		const char *col = strchr(keys[i], ':');  // unless inilib is broken
		const char *v   = iniparser_getstring(d, keys[i], "");
		if (strlen(v) == 0) {
			fprintf(stderr, "Mapping \"%s\" is invalid\n", keys[i]);
			exit(1);
		}
		uint16_t    k   = std::stoi(col + 1);
		mappings_in->insert({ k, v });
	}

	delete [] keys;
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

	DOLOG(logger::ll_info, "UDP server starting...");

	dictionary *d = iniparser_load(cfg_file.c_str());
	for(int i=0; i<iniparser_getnsec(d); i++) {
		std::string section_name = iniparser_getsecname(d, i);
		if (section_name != "global" && section_name != "specific" && section_name != "mappings") {
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
	std::map<uint16_t, std::string> mappings_in;
	load_mappings(&mappings_in, d);
	iniparser_freedict(d);

	signal(SIGINT, sig_handler);

	shm_message_queue shm(name, msg_queue_size);
	if (shm.begin() == false) {
		fprintf(stderr, "Cannot initialize shared memory segment \"%s\"\n", name.c_str());
		return 1;
	}

	run(&shm, out_name, mappings_in);

	return 0;
}
