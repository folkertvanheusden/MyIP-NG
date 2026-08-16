#include <atomic>
#include <cassert>
#include <cerrno>
#include <cinttypes>
#include <csignal>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <iniparser/iniparser.h>

#include "common.h"
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
	m_reply->msg_nr = msg_nr;
	memcpy(m_reply->data, reply.c_str(), m_reply->size);
	shm_resolver->send_message(to, m_reply, false);
	free(m_reply);
}

void run_resolver(shm_message_queue *const shm_resolver, std::vector<request> *const requests, std::mutex & requests_lock,
		  const addr_ip4 & ip4_addr,
		  const addr_mac & mac,
		  const std::string & out_name,
		  shm_message_queue *const shm_out,
		  std::map<addr_ip4, addr_mac, addr> *arp_cache, std::mutex & arp_cache_lock)
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

		addr_mac SHA = mac;
		addr_ip4 SPA(4);
		addr_mac THA(bc_addr, 6);
		addr_ip4 TPA(4);

		request r;

		if (parts[0] == "search-mac") {  // search MAC by IP4
			r.ip4 = addr_ip4(parts[1], ".", false);
			TPA   = r.ip4.value();

			// if me, return right away
			if (r.ip4.value() == ip4_addr) {
				auto reply = "ip4:" + r.ip4.value().to_str('.', false) + "=mac:" + SHA.to_str(':', true);
				push_resolver_reply(shm_resolver, m->sender, reply, m->msg_nr);
				free(m);
				continue;
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
	    const addr_mac & mac_addr, const addr_ip4 & ip4_addr,
	    std::vector<request> *const requests, std::mutex & requests_lock,
	    shm_message_queue *const shm_resolver,
	    std::map<addr_ip4, addr_mac, addr> *arp_cache, std::mutex & arp_cache_lock)
{
	while(!stop_flag) {
		shm_message_queue::message *m = shm->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_new, { });
		if (!m)
			continue;

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
				if (TPA == ip4_addr) {
					uint8_t payload_out[28];
					memcpy(payload_out, pl, 28);
					SHA.get(&payload_out[18]);  // set THA to SHA
					// this is a reply
					payload_out[6] = 0;
					payload_out[7] = 2;
					// MAC address
					mac_addr.get(&payload_out[8]);  // me
					SPA.get(&payload_out[24]);  // who will receive
					TPA.get(&payload_out[14]);  // who will sent [mne]
					assert(SPA != TPA);

					// push to Ethernet
					uint8_t from[6] { };
					mac_addr.get(from);
					uint8_t to  [6] { };
					SHA.get(to);
					auto temp_msg_nr = m->msg_nr;

					DOLOG(logger::ll_debug, "Sending reply with MAC address %s",
							mac_addr.to_str(':', true).c_str());

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

std::optional<uint64_t> send_meta_request(shm_message_queue *const shm_meta, const std::string & peer_name, const std::string & request)
{
        shm_message_queue::message *meta_request_msg = allocate_shm_message(request.size());
        meta_request_msg->type = shm_message_queue::msg_new;
        memcpy(meta_request_msg->data, request.c_str(), request.size());
        if (shm_meta->send_message(peer_name, meta_request_msg, true)) {
                uint64_t msg_nr = meta_request_msg->msg_nr;
                free(meta_request_msg);
                return msg_nr;
        }

        free(meta_request_msg);
        return { };
}

std::pair<addr_mac, addr_ip4> cfg_runtime(shm_message_queue *const shm_meta,
		const std::string & meta_name_Ethernet_server, const std::string & meta_name_ip4_server)
{
	std::optional<addr_mac> mac_addr;
	std::optional<addr_ip4> ip4_addr;

	while(!stop_flag) {
		if (mac_addr.has_value() == false) {
			DOLOG(logger::ll_debug, "Requesting MAC address from \"%s\"", meta_name_Ethernet_server.c_str());

			auto msg_nr = send_meta_request(shm_meta, meta_name_Ethernet_server, "get-mac");
			if (msg_nr.has_value()) {
				DOLOG(logger::ll_debug, "Waiting for msg-id %" PRIu64, msg_nr.value());
				auto *reply = shm_meta->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_reply, msg_nr.value());
				if (reply) {
					std::string reply_str(reinterpret_cast<const char *>(reply->data), reply->size);
					if (reply_str.substr(0, 4) == "mac=")
						mac_addr = addr(reply_str.substr(4), ":", true);
					free(reply);
				}
			}
		}

		if (ip4_addr.has_value() == false) {
			DOLOG(logger::ll_debug, "Requesting IP4 address from \"%s\"", meta_name_ip4_server.c_str());

			auto msg_nr = send_meta_request(shm_meta, meta_name_ip4_server, "get-ip4");
			if (msg_nr.has_value()) {
				auto *reply = shm_meta->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_reply, msg_nr.value());
				if (reply) {
					std::string reply_str(reinterpret_cast<const char *>(reply->data), reply->size);
					if (reply_str.substr(0, 4) == "ip4=")
						ip4_addr = addr(reply_str.substr(4), ".", false);
					free(reply);
				}
			}
		}

		if (mac_addr.has_value() == true && ip4_addr.has_value() == true)
			return { mac_addr.value(), ip4_addr.value() };

		usleep(500'000);
	}

	return { };
}

void run(shm_message_queue *const shm,
         addr_mac & mac_addr, addr_ip4 & ip4_addr,
	 std::vector<request> *const requests, std::mutex & requests_lock,
	 shm_message_queue *const shm_resolver,
	 const std::string & out_name,
	 std::map<addr_ip4, addr_mac, addr> *arp_cache, std::mutex & arp_cache_lock)
{
	DOLOG(logger::ll_debug, "Starting processing");

	std::thread res([&] { run_resolver(shm_resolver, requests, requests_lock, ip4_addr, mac_addr, out_name, shm, arp_cache, arp_cache_lock); });
	std::thread rx ([&] { run_in(shm, mac_addr, ip4_addr, requests, requests_lock, shm_resolver, arp_cache, arp_cache_lock); });
	rx.join();
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
	std::string out_name = iniparser_getstring(d, "global:out-name",  "");
	if (out_name.empty()) {
		fprintf(stderr, "\"out-name\" under \"global\" missing\n");
		return 1;
	}
	std::string resolver_name = iniparser_getstring(d, "global:resolver-name",  "");
	if (resolver_name.empty()) {
		fprintf(stderr, "\"resolver-name\" under \"global\" missing\n");
		return 1;
	}
	std::string meta_name = iniparser_getstring(d, "global:meta-name",  "");
	if (meta_name.empty()) {
		fprintf(stderr, "\"meta-name\" under \"global\" missing\n");
		return 1;
	}
	std::string ether_meta_name = iniparser_getstring(d, "global:ether-meta-name",  "");
	if (ether_meta_name.empty()) {
		fprintf(stderr, "\"ether-meta-name\" under \"global\" missing\n");
		return 1;
	}
	std::string ip4_meta_name = iniparser_getstring(d, "global:ip4-meta-name",  "");
	if (ip4_meta_name.empty()) {
		fprintf(stderr, "\"ip4-meta-name\" under \"global\" missing\n");
		return 1;
	}
	int msg_queue_size = iniparser_getint(d, "specific:msg-queue-size", 0);
	if (msg_queue_size == 0) {
		msg_queue_size = 16384;
		fprintf(stderr, "Using default msg queue size of %d bytes\n", msg_queue_size);
	}
	int msg_queue_size_resolver = iniparser_getint(d, "specific:msg-queue-size-resolver", 2048);
	iniparser_freedict(d);

	std::vector<request> requests;
	std::mutex           requests_lock;

	signal(SIGINT, sig_handler);

	shm_message_queue *shm = create_shm(name, msg_queue_size);
	if (shm == nullptr)
		return 1;

	shm_message_queue *shm_resolver = create_shm(resolver_name, msg_queue_size_resolver);
	if (shm_resolver == nullptr)
		return 1;

	shm_message_queue *shm_meta = create_shm(meta_name, META_SHM_SIZE);
	if (shm_meta == nullptr)
		return 1;

	auto     addresses = cfg_runtime(shm_meta, ether_meta_name, ip4_meta_name);
	addr_mac mac_addr  = addresses.first;
	addr_ip4 ip4_addr  = addresses.second;
	delete shm_meta;

	std::map<addr_ip4, addr_mac, addr> cache;
	std::mutex cache_lock;

	run(shm, mac_addr, ip4_addr, &requests, requests_lock, shm_resolver, out_name, &cache, cache_lock);

	delete shm_resolver;
	delete shm;

	return 0;
}
