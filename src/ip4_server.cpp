#include <atomic>
#include <cassert>
#include <cerrno>
#include <csignal>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <iniparser/iniparser.h>

#include "utils/addresses.h"
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

void run_in(shm_message_queue *const shm, const std::pair<addr_ip4, int> & listen_addr,
            const std::map<uint8_t, std::string> & mappings_in, const std::string & icmp_name)
{
	while(!stop_flag) {
		shm_message_queue::message *m = shm->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_any, { });
		if (!m)
			continue;

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

		if (pl_len < 20) {
			DOLOG(logger::ll_debug, "IP4 payload < 20 bytes");
		}
		else if (int version = pl[0] >> 4; version != 0x04) {
			DOLOG(logger::ll_debug, "Not an IP4 packet");
		}
		else if (pl[8] <= 1) {  // TTL exceeded?
			DOLOG(logger::ll_debug, "TTL exceeded");
		}
		else {
			int header_size = (pl[0] & 15) * 4;
			int ip_size     = (pl[2] << 8) | pl[3];
			int protocol    = pl[9];

			auto it = mappings_in.find(protocol);

			addr_ip4 ip4_src(&pl[12], 4);
			addr_ip4 ip4_dst(&pl[16], 4);

			if (header_size > ip_size)
				DOLOG(logger::ll_debug, "Invalid IP4 header size");
			else if (ip_size > pl_len)
				DOLOG(logger::ll_debug, "Invalid IP4 size");
			else if (it == mappings_in.end()) {
				DOLOG(logger::ll_debug, "Protocol %d not known", protocol);
				// TODO send ICMP -> icmp_name
			}
			else if (ip4_dst != listen_addr.first)
				DOLOG(logger::ll_debug, "%s is not for this instance", ip4_dst.to_str('.', false).c_str());
			else {
				// TODO fragmentation

				// wrap IP4
				auto wrapped_ip4 = wrap_message(
					  ip4_src.length(), ip4_src.get(),
					  ip4_dst.length(), ip4_dst.get(),
                                          ip_size - header_size, &pl[header_size]);

				auto *fully_wrapped = wrap_message(
						from_len, from,
						to_len,   to,
						wrapped_ip4.second, wrapped_ip4.first,
						{ });
				free(wrapped_ip4.first);

				shm->send_message(it->second, fully_wrapped, false);

				free(fully_wrapped);
			}
		}

		free(m);
	}
}

void run_out(shm_message_queue *const shm, const std::pair<addr_ip4, int> & listen_addr,
             const std::map<std::string, uint8_t> & mappings_out)
{
	while(!stop_flag) {
		shm_message_queue::message *m = shm->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_any, { });
		if (!m)
			continue;

		// TODO
	}
}

void announcer(shm_message_queue *const shm, const std::string & announce_ip4_addr, const addr_ip4 & addr)
{
	const std::string msg = std::format("addip4={0}", addr.to_str('.', false));
	shm_message_queue::message *m = allocate_shm_message(msg.size());
	m->type = shm_message_queue::msg_new;
	m->size = msg.size();
	memcpy(m->data, msg.c_str(), m->size);

	int i = 0;
	while(!stop_flag) {
		if (++i < 10) {
			usleep(SLEEP_INTERVAL_MS * 1000);
			continue;
		}
		i = 0;

		// announce-ip4-addr to ARP process
		DOLOG(logger::ll_debug, "Announce \"%s\" to %s", msg.c_str(), announce_ip4_addr.c_str());
		shm->send_message(announce_ip4_addr, m, false);
	}

	free(m);
}

void run(shm_message_queue *const shm, const std::string & announce_ip4_addr, const std::pair<addr_ip4, int> & listen_addr,
         const std::map<uint8_t, std::string> & mappings_in,
         const std::map<std::string, uint8_t> & mappings_out,
	 const std::string & icmp_name,
	 shm_message_queue *const shm_out)
{
	std::thread rx([&] { run_in (shm,     listen_addr, mappings_in,  icmp_name); });
	std::thread tx([&] { run_out(shm_out, listen_addr, mappings_out           ); });
        std::thread announce([shm, announce_ip4_addr, listen_addr] { announcer(shm, announce_ip4_addr, listen_addr.first); });
        announce.join();
	rx.join();
}

void load_mappings(std::map<uint8_t, std::string> *const mappings_in, std::map<std::string, uint8_t> *const mappings_out, const dictionary *const d)
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
		uint16_t    k   = std::stoi(col + 1, nullptr, 16);
		mappings_in ->insert({ k, v });
		mappings_out->insert({ v, k });
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

	DOLOG(logger::ll_info, "IP4 server starting...");

	dictionary *d = iniparser_load(cfg_file.c_str());
	for(int i=0; i<iniparser_getnsec(d); i++) {
		std::string section_name = iniparser_getsecname(d, i);
		if (section_name != "global" && section_name != "specific" && section_name != "mappings") {
			fprintf(stderr, "Section \"%s\" in configuration file is unknown\n", section_name.c_str());
			return 1;
		}
	}
	std::string name = iniparser_getstring(d, "global:name",  "");
	if (name.empty()) {
		fprintf(stderr, "\"name\" under \"global\" missing\n");
		return 1;
	}
	std::string out_name = iniparser_getstring(d, "global:out-name",  "");
	if (out_name.empty()) {
		fprintf(stderr, "\"out-name\" under \"global\" missing\n");
		return 1;
	}
	std::string cfg_name = iniparser_getstring(d, "global:cfg-name",  "");
	if (cfg_name.empty()) {
		fprintf(stderr, "\"cfg-name\" under \"global\" missing\n");
		return 1;
	}
	std::string icmp_name = iniparser_getstring(d, "specific:icmp-name",  "");
	if (icmp_name.empty()) {
		fprintf(stderr, "\"icmp-name\" under \"specific\" missing\n");
		return 1;
	}
	int msg_queue_size = iniparser_getint(d, "specific:msg-queue-size", 0);
	if (msg_queue_size == 0) {
		msg_queue_size = 16384;
		fprintf(stderr, "Using default msg queue size of %d bytes\n", msg_queue_size);
	}
	std::string listen_addr_str = iniparser_getstring(d, "specific:listen-addr",  "");
	if (listen_addr_str.empty()) {
		fprintf(stderr, "\"listen-addr\" under \"specific\" missing\n");
		return 1;
	}
	auto slash = listen_addr_str.find('/');
	if (slash == std::string::npos) {
		fprintf(stderr, "\"listen-addr\": CIDR missing\n");
		return 1;
	}
	int cidr = std::stoi(listen_addr_str.substr(slash + 1));
	addr_ip4 listen_addr(listen_addr_str.substr(0, slash), ".", false);
        std::string announce_ip4_addr = iniparser_getstring(d, "specific:announce-ip4-addr", "");
        if (announce_ip4_addr.empty()) {
                fprintf(stderr, "\"announce-ip4-addr\" under \"specific\" missing\n");
                return 1;
        }
	std::map<uint8_t, std::string> mappings_in;
	std::map<std::string, uint8_t> mappings_out;
	load_mappings(&mappings_in, &mappings_out, d);
	iniparser_freedict(d);

	signal(SIGINT, sig_handler);

	shm_message_queue shm(name, msg_queue_size);
	if (shm.begin() == false) {
		fprintf(stderr, "Cannot initialize shared memory segment\n");
		return 1;
	}

	shm_message_queue shm_out(out_name, msg_queue_size);
	if (shm.begin() == false) {
		fprintf(stderr, "Cannot initialize shared memory segment\n");
		return 1;
	}

	run(&shm, announce_ip4_addr, { listen_addr, cidr }, mappings_in, mappings_out, icmp_name, &shm_out);

	return 0;
}
