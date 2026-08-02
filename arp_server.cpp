#include <atomic>
#include <cassert>
#include <cerrno>
#include <csignal>
#include <mutex>
#include <set>
#include <thread>
#include <iniparser/iniparser.h>

#include "gen.h"
#include "log.h"
#include "shm.h"
#include "shm_message.h"
#include "str_utils.h"


constexpr const uint8_t bc_addr[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

struct addr {
	uint8_t *a     { nullptr };
	size_t   a_len { 0       };

	addr() {  // for comparator
	}

	addr(const std::string & what, const std::string & seperator, const bool is_hex) {
		auto parts = split(what, seperator);
		a_len = parts.size();
		a = new uint8_t[a_len];
		if (is_hex) {
			for(size_t i=0; i<a_len; i++)
				a[i] = std::stoi(parts[i], nullptr, 16);
		}
		else {
			for(size_t i=0; i<a_len; i++)
				a[i] = std::stoi(parts[i]);
		}
	}

	virtual ~addr() {
		delete [] a;
	}

	addr & operator=(const addr & input) {
		a = new uint8_t[input.a_len];
		memcpy(a, input.a, input.a_len);
		a_len = input.a_len;
		return *this;
	}

	bool operator()(const addr & lhs, const addr & rhs) const
	{
		assert(lhs.a_len == rhs.a_len);
		return memcmp(lhs.a, rhs.a, a_len);
	}
};

typedef addr addr_ip4;
typedef addr addr_mac;

std::atomic_bool stop_flag { false };

void sig_handler(int sig)
{
	stop_flag = true;
}

void run_in(shm_message_queue *const shm,
	    const addr_mac & mappings_in,                  std::mutex & mac_lock,
            const std::set<addr_ip4, addr> & mappings_out, std::mutex & ip4_lock)
{
	while(!stop_flag) {
		shm_message_queue::message *m = shm->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_new, { });
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

		if (from_len != 6 || to_len != 6) {
			DOLOG(logger::ll_error, "Unexpected address lengths!");
			free(m);
			continue;
		}

		if (pl_len == 0) {
			DOLOG(logger::ll_warning, "Empty payload");
			free(m);
			continue;
		}

#if 0
		auto it = mappings_out.find(m->sender);
		if (it == mappings_out.end()) {
			DOLOG(logger::ll_debug, "No mapping for %s", m->sender);
			free(m);
			continue;
		}

		// TODO
#endif
		free(m);
	}
}

void run_cfg(addr_mac & mappings_in,                  std::mutex & mac_lock,
	     std::set<addr_ip4, addr> & mappings_out, std::mutex & ip4_lock,
	     shm_message_queue *const shm_cfg)
{
	while(!stop_flag) {
		shm_message_queue::message *m = shm_cfg->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_new, { });
		if (!m)
			continue;

		std::string kv(reinterpret_cast<const char *>(m->data), m->size);
		auto parts = split(kv, "=");
		if (parts.size() != 2) {
			DOLOG(logger::ll_error, "Not a command pair via shared configuration memory (%s)", kv.c_str());
			free(m);
			continue;
		}

		if (parts[0] == "setmac") {
			addr new_mac(parts[1], ":", true);
			std::unique_lock<std::mutex> lck(mac_lock);
			mappings_in = new_mac;
		}
		else if (parts[1] == "addip4") {
			addr new_ip4(parts[1], ".", false);
			std::unique_lock<std::mutex> lck(ip4_lock);
			mappings_out.insert(new_ip4);
		}
		else if (parts[1] == "delip4") {
			addr del_ip4(parts[1], ".", false);
			std::unique_lock<std::mutex> lck(ip4_lock);
			mappings_out.erase(del_ip4);
		}

		free(m);
	}
}

void run(shm_message_queue *const shm,
         addr_mac & mac,                      std::mutex & mac_lock,
         std::set<addr_ip4, addr> & ip4_list, std::mutex & ip4_lock,
	 shm_message_queue *const shm_cfg)
{
	std::thread cfg([&] { run_cfg(mac, mac_lock, ip4_list, ip4_lock, shm_cfg); });
	std::thread rx ([&] { run_in (shm, mac, mac_lock, ip4_list, ip4_lock    ); });
	rx.join();
	cfg.join();
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

	DOLOG(logger::ll_info, "ARP server starting...");

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
	std::string cfg_name = iniparser_getstring(d, "global:cfg-name",  "");
	if (cfg_name.empty()) {
		fprintf(stderr, "\"cfg-name\" under \"global\" missing\n");
		return 1;
	}
	int msg_queue_size = iniparser_getint(d, "specific:msg-queue-size", 0);
	if (msg_queue_size == 0) {
		msg_queue_size = 16384;
		fprintf(stderr, "Using default msg queue size of %d bytes\n", msg_queue_size);
	}
	std::mutex m_in_lock;
	addr_mac   mac;
	std::mutex m_out_lock;
	std::set<addr_ip4, addr> ip4_list;
	iniparser_freedict(d);

	signal(SIGINT, sig_handler);

	shm_message_queue shm(name, msg_queue_size);
	if (shm.begin() == false) {
		fprintf(stderr, "Cannot initialize shared memory segment\n");
		return 1;
	}

	shm_message_queue shm_cfg(cfg_name, msg_queue_size);
	if (shm_cfg.begin() == false) {
		fprintf(stderr, "Cannot initialize shared memory segment for configuration channel\n");
		return 1;
	}

	run(&shm, mac, m_in_lock, ip4_list, m_out_lock, &shm_cfg);

	return 0;
}
