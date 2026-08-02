#include <atomic>
#include <cassert>
#include <cerrno>
#include <csignal>
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

void run_in(shm_message_queue *const shm,
	    const addr_mac & mappings_in,                  std::mutex & mac_lock,
            const std::set<addr_ip4, addr> & mappings_out, std::mutex & ip4_lock)
{
	while(!stop_flag) {
		shm_message_queue::message *m = shm->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_new, { });
		if (!m)
			continue;

		{
			std::unique_lock<std::mutex> lck(ip4_lock);
			if (mappings_out.empty()) {
				DOLOG(logger::ll_error, "No IP4 addresses known yet, dropping packet");
				free(m);
				continue;
			}
		}

		{
			std::unique_lock<std::mutex> lck(mac_lock);
			if (mappings_in.a_len == 0) {
				DOLOG(logger::ll_error, "No MAC address known yet, dropping packet");
				free(m);
				continue;
			}
		}

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

		if (pl_len < 28) {
			DOLOG(logger::ll_debug, "arp payload < 28 bytes");
		}
		else if (uint16_t hw_type = get_uint16(pl + 0); hw_type != 1) {  // Ethernet?
			DOLOG(logger::ll_debug, "arp hardware type is not Ethernet (%u)", hw_type);
		}
		else if (uint16_t proto_type = get_uint16(pl + 2); proto_type != 0x0800) {  // IPv4?
			DOLOG(logger::ll_debug, "arp protocol type is not IPv4 (%04x)", proto_type);
		}
		else if (uint8_t hw_length = pl[4]; hw_length != 6) {  // Ethernet?
			DOLOG(logger::ll_debug, "arp hardware length != 6 (%u)", hw_length);
		}
		else if (uint8_t proto_length = pl[5]; proto_length != 4) {  // IPv4?
			DOLOG(logger::ll_debug, "arp protocol length != 4 (%u)", proto_length);
		}
		else {
			addr_mac SHA(pl +  8, 6);
			addr_ip4 SPA(pl + 14, 4);
			addr_mac THA(pl + 18, 6);
			addr_ip4 TPA(pl + 24, 4);

			uint16_t operation = get_uint16(pl + 6);

			DOLOG(logger::ll_debug, "ARP%04x: THA: %s, SHA: %s, TPA: %s, SPA: %s",
					operation,
					THA.to_str(':', true ).c_str(), SHA.to_str(':', true ).c_str(),
					TPA.to_str('.', false).c_str(), SPA.to_str('.', false).c_str());

			if (operation == 1) {  // request
					       // see if TPA is known
				bool known = false;
				{
					std::unique_lock<std::mutex> lck(ip4_lock);
					auto it = mappings_out.find(TPA);
					if (it != mappings_out.end())
						known = true;
				}

				if (known) {
					DOLOG(logger::ll_debug, "arp sending reply with MAC address %s", mappings_in.to_str(':', true).c_str());

					uint8_t payload_out[28];
					memcpy(payload_out, pl, 28);
					SHA.get(&payload_out[18]);  // set THA to SHA
					// this is a reply
					payload_out[6] = 0;
					payload_out[7] = 2;
					// MAC address
					{
						std::unique_lock<std::mutex> lck(mac_lock);
						mappings_in.get(&payload_out[8]);
					}
					// swap IP4 addresses
					for(int i=0; i<4; i++)
						std::swap(payload_out[i + 14], payload_out[i + 24]);

					// push to Ethernet
					uint8_t from[6] { };
					mappings_in.get(from);
					uint8_t to  [6] { };
					SHA.get(to);
					shm_message_queue::message *m_out = wrap_message(sizeof from, from,
							sizeof to, to,
							sizeof(payload_out), payload_out,
							m->msg_nr);
					shm->send_message(m->sender, m_out, false);

					free(m_out);
				}
				else {
					DOLOG(logger::ll_debug, "Requested IP address (%s) not known", TPA.to_str('.', false).c_str());
				}
			}
			else if (operation == 2) {  // reply
			}
			else {
				DOLOG(logger::ll_debug, "arp unexpected operation (%u)", operation);
			}
		}

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
ip4_list.insert(addr("192.168.1.2", ".", false));

	run(&shm, mac, m_in_lock, ip4_list, m_out_lock, &shm_cfg);

	return 0;
}
