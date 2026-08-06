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

struct request {
	// one must be set
	std::optional<addr_mac> mac;
	std::optional<addr_ip4> ip4;
	std::string searched_by;
	uint64_t    msg_nr;
};

void push_resolver_reply(shm_message_queue *const shm_resolver, const std::string & to, const std::string & reply, const uint64_t msg_nr)
{
	DOLOG(logger::ll_debug, "Pushing reply \"%s\" to \"%s\"", reply.c_str(), to.c_str());
	shm_message_queue::message *m_reply = allocate_shm_message(reply.size());
	m_reply->type   = shm_message_queue::msg_reply;
	m_reply->size   = reply.size();
	m_reply->msg_nr = msg_nr;
	memcpy(m_reply->data, reply.c_str(), m_reply->size);
	shm_resolver->send_message(to, m_reply, false);
	free(m_reply);
}

void run_resolver(shm_message_queue *const shm_resolver, std::vector<request> *const requests, std::mutex & requests_lock,
		  const std::set<addr_ip4, decltype(set_cmp)> & ip4_list, std::mutex & ip4_lock,
		  const addr_mac & mac,                                   std::mutex & mac_lock,
		  const std::string & out_name,
		  shm_message_queue *const shm_out,
		  std::map<addr_ip4, addr_mac, decltype(set_cmp)> *arp_cache, std::mutex & arp_cache_lock)
{
	while(!stop_flag) {
		shm_message_queue::message *m = shm_resolver->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_new, { });
		if (!m)
			continue;

		std::string kv(reinterpret_cast<const char *>(m->data), m->size);
		auto parts = split(kv, "=");
		if (parts.size() != 2) {
			DOLOG(logger::ll_error, "Not a command pair via shared configuration memory (%s)", kv.c_str());
			free(m);
			continue;
		}

		mac_lock.lock();
		addr_mac SHA = mac;
		mac_lock.unlock();
		addr_ip4 SPA(4);
		addr_mac THA(bc_addr, 6);
		addr_ip4 TPA(4);

		request r;

		if (parts[0] == "search-mac") {  // search MAC by IP4
			r.ip4 = addr_ip4(parts[1], ".", false);
			TPA   = r.ip4.value();

			// if me, return right away
			{
				std::unique_lock<std::mutex> lck(ip4_lock);
				if (ip4_list.find(r.ip4.value()) != ip4_list.end()) {
					lck.unlock();
					auto reply = "ip4:" + r.ip4.value().to_str('.', false) + "=mac:" + SHA.to_str(':', true);
					push_resolver_reply(shm_resolver, m->sender, reply, m->msg_nr);
					free(m);
					continue;
				}

				if (ip4_list.empty() == false)
					SPA = *ip4_list.begin();
				else
					DOLOG(logger::ll_info, "Cannot set TPA for ARP: not known yet");
			}

			// in cache?
			{
				std::unique_lock<std::mutex> lck(arp_cache_lock);
				auto it = arp_cache->find(r.ip4.value());
				if (it != arp_cache->end()) {
					lck.unlock();
					auto reply = "ip4:" + r.ip4.value().to_str('.', false) + "=mac:" + it->second.to_str(':', true);
					DOLOG(logger::ll_debug, "ARP cache hit: \"%s\"", reply.c_str());
					push_resolver_reply(shm_resolver, m->sender, reply, m->msg_nr);
					free(m);
					continue;
				}
			}
		}
		else if (parts[0] == "search-ip4") {  // search IP4 by MAC
			r.mac = addr_mac(parts[1], ":", true);
			SHA   = r.mac.value();
		}
		else {
			DOLOG(logger::ll_error, "Invalid command (%s)", kv.c_str());
			free(m);
			continue;
		}

		r.searched_by = m->sender;

		{
			std::unique_lock<std::mutex> lck(requests_lock);
			requests->push_back(r);
		}

		DOLOG(logger::ll_debug, "Sending ARP request, THA: %s, SHA: %s, TPA: %s, SPA: %s",
					THA.to_str(':', true ).c_str(), SHA.to_str(':', true ).c_str(),
					TPA.to_str('.', false).c_str(), SPA.to_str('.', false).c_str());

		uint8_t request[44] { 0 };
		request[1] = 1;  // HTYPE Ethernet
		request[2] = 0x08;  // PTYPE IP4
		request[3] = 0x00;
		request[4] = 6;  // HLEN (Ethernet)
		request[5] = 4;  // PLEN (IP4)
		request[6] = 0x00;  // OPER
		request[7] = 1;

		int sha_offset = 8;
		int spa_offset = 8 + 6;
		int tha_offset = spa_offset + 4;
		int tpa_offset = tha_offset + 6;

		SHA.get(&request[sha_offset]);
		SPA.get(&request[spa_offset]);
		THA.get(&request[tha_offset]);  // target = bc_addr
		TPA.get(&request[tpa_offset]);

		shm_message_queue::message *m_out = wrap_message_down(
				SHA.length(),   SHA.get(),
				sizeof bc_addr, bc_addr,
				sizeof request, request,
				{ });
		// send request to link layer
		shm_out->send_message(out_name, m_out, false);
		free(m_out);

		free(m);
	}
}

void register_resolve_reply(shm_message_queue *const shm_resolver,
		            std::vector<request> *const requests, std::mutex & requests_lock,
			    const addr_mac & SHA, const addr_ip4 & SPA)
{
	std::unique_lock<std::mutex> lck(requests_lock);
	for(size_t i=0; i<requests->size();) {
		std::string reply;

		auto & item = requests->at(i);
		if (item.mac.has_value() && item.mac.value() == SHA) {
			reply = "mac:" + item.mac.value().to_str(':', true) + "=ip4:" + SPA.to_str('.', false);
		}
		else if (item.ip4.has_value() && item.ip4.value() == SPA) {
			reply = "ip4:" + item.ip4.value().to_str('.', false) + "=mac:" + SHA.to_str(':', true);
		}

		if (reply.empty() == false) {
			push_resolver_reply(shm_resolver, item.searched_by, reply, item.msg_nr);
			requests->erase(requests->begin() + i);
		}
		else {
			i++;
		}
	}
}

// Ethernet -> ARP
void run_in(shm_message_queue *const shm,
	    const addr_mac & mappings_in,                               std::mutex & mac_lock,
            const std::set<addr_ip4, decltype(set_cmp)> & mappings_out, std::mutex & ip4_lock,
	    std::vector<request> *const requests,                       std::mutex & requests_lock,
	    shm_message_queue *const shm_resolver,
	    std::map<addr_ip4, addr_mac, decltype(set_cmp)> *arp_cache, std::mutex & arp_cache_lock)
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
					uint8_t payload_out[28];
					memcpy(payload_out, pl, 28);
					SHA.get(&payload_out[18]);  // set THA to SHA
					// this is a reply
					payload_out[6] = 0;
					payload_out[7] = 2;
					// MAC address
					{
						std::unique_lock<std::mutex> lck(mac_lock);
						mappings_in.get(&payload_out[8]);  // me
					}
					SPA.get(&payload_out[24]);  // who will receive
					TPA.get(&payload_out[14]);  // who will sent [mne]
					assert(SPA != TPA);

					// push to Ethernet
					uint8_t from[6] { };
					mappings_in.get(from);
					uint8_t to  [6] { };
					SHA.get(to);
					auto temp_msg_nr = m->msg_nr;

					DOLOG(logger::ll_debug, "Sending reply with MAC address %s",
							mappings_in.to_str(':', true).c_str());

					shm_message_queue::message *m_out = wrap_message_down(
							sizeof from,         from,
							sizeof to,           to,
							sizeof(payload_out), payload_out,
							temp_msg_nr);
					shm->send_message(m->sender, m_out, false);

					free(m_out);
				}
				else {
					DOLOG(logger::ll_debug, "Requested IP address (%s) not known", TPA.to_str('.', false).c_str());
				}
			}
			else if (operation == 2) {  // reply
				addr_mac SHA(pl +  8, 6);
				addr_ip4 SPA(pl + 14, 4);

				DOLOG(logger::ll_debug, "ARP reply received: %s is at %s",
						SPA.to_str('.', false).c_str(),
						SHA.to_str(':', true ).c_str());

				{
					std::unique_lock<std::mutex> lck(arp_cache_lock);
					arp_cache->insert({ SPA, SHA });
				}

				register_resolve_reply(shm_resolver, requests, requests_lock, SHA, SPA);
			}
			else {
				DOLOG(logger::ll_debug, "arp unexpected operation (%u)", operation);
			}
		}

		free(m);
	}
}

void run_cfg(addr_mac & mappings_in,                               std::mutex & mac_lock,
	     std::set<addr_ip4, decltype(set_cmp)> & mappings_out, std::mutex & ip4_lock,
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

		DOLOG(logger::ll_debug, "Received cfg item: \"%s\"", kv.c_str());

		if (parts[0] == "setmac") {
			addr new_mac(parts[1], ":", true);
			std::unique_lock<std::mutex> lck(mac_lock);
			mappings_in = new_mac;
		}
		else if (parts[0] == "addip4") {
			addr new_ip4(parts[1], ".", false);
			std::unique_lock<std::mutex> lck(ip4_lock);
			mappings_out.insert(new_ip4);
		}
		else if (parts[0] == "delip4") {
			addr del_ip4(parts[1], ".", false);
			std::unique_lock<std::mutex> lck(ip4_lock);
			mappings_out.erase(del_ip4);
		}

		free(m);
	}
}

void run(shm_message_queue *const shm,
         addr_mac & mac,                                   std::mutex & mac_lock,
         std::set<addr_ip4, decltype(set_cmp)> & ip4_list, std::mutex & ip4_lock,
	 shm_message_queue *const shm_cfg,
	 std::vector<request> *const requests, std::mutex & requests_lock,
	 shm_message_queue *const shm_resolver,
	 const std::string & out_name,
	 std::map<addr_ip4, addr_mac, decltype(set_cmp)> *arp_cache, std::mutex & arp_cache_lock)
{
	std::thread res([&] { run_resolver(shm_resolver, requests, requests_lock, ip4_list, ip4_lock, mac, mac_lock, out_name, shm, arp_cache, arp_cache_lock); });
	std::thread cfg([&] { run_cfg(mac, mac_lock, ip4_list, ip4_lock, shm_cfg); });
	std::thread rx ([&] { run_in (shm, mac, mac_lock, ip4_list, ip4_lock, requests, requests_lock, shm_resolver, arp_cache, arp_cache_lock); });
	rx.join();
	cfg.join();
	res.join();
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
	std::string out_name = iniparser_getstring(d, "global:out-name",  "");
	if (out_name.empty()) {
		fprintf(stderr, "\"out-name\" under \"global\" missing\n");
		return 1;
	}
	std::string resolver_name = iniparser_getstring(d, "specific:resolver-name",  "");
	if (resolver_name.empty()) {
		fprintf(stderr, "\"resolver-name\" under \"specific\" missing\n");
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
	std::set<addr_ip4, decltype(set_cmp)> ip4_list;
	iniparser_freedict(d);

	std::vector<request> requests;
	std::mutex           requests_lock;

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

	shm_message_queue shm_resolver(resolver_name, msg_queue_size);
	if (shm_resolver.begin() == false) {
		fprintf(stderr, "Cannot initialize shared memory segment for resolver channel\n");
		return 1;
	}

	std::map<addr_ip4, addr_mac, decltype(set_cmp)> cache;
	std::mutex cache_lock;

	run(&shm, mac, m_in_lock, ip4_list, m_out_lock, &shm_cfg, &requests, requests_lock, &shm_resolver, out_name, &cache, cache_lock);

	return 0;
}
