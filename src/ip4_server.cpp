#include <algorithm>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cinttypes>
#include <csignal>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <vector>
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

void send_icmp_error(shm_message_queue *const shm, const std::string & icmp_error_name, const int type, const int code, const std::pair<const uint8_t *, size_t> & full_pkt, const addr_ip4 & to, const addr_ip4 & me)
{
	uint8_t extra_data[2];
	extra_data[0] = type;
	extra_data[1] = code;

	auto *wrapped = wrap_message_up(
			full_pkt.second,   full_pkt.first,
			me.length(),       me.get(),
			to.length(),       to.get(),
			sizeof extra_data, extra_data,
			{ });

	if (shm->send_message(icmp_error_name, wrapped, false) == false)
		DOLOG(logger::ll_warning, "Cannot send ICMP message");
	else
		DOLOG(logger::ll_warning, "ICMP message type %d code %d queued", type, code);

	free(wrapped);
}

static uint64_t calc_session_id(const addr & from, const addr & to, const uint16_t protocol, const uint16_t id)
{
        size_t   from_len = from.length();

        size_t   session_id_buffer_len = 2 + 2 + from_len + to.length();
        uint8_t *session_id_buffer     = new uint8_t[session_id_buffer_len]();

        *reinterpret_cast<uint16_t *>(session_id_buffer + 0) = protocol;
        *reinterpret_cast<uint16_t *>(session_id_buffer + 2) = id;
        from.get(&session_id_buffer[4]);
        to  .get(&session_id_buffer[4 + from_len]);

        auto rc = fletcher64(session_id_buffer, session_id_buffer_len);
        delete [] session_id_buffer;

        return rc;
}

struct packet {
	uint8_t *data;
	size_t   len;
	bool     full_size_known;
	std::vector<std::pair<uint16_t, uint16_t> > fragments;
};

bool is_complete(packet *const p)
{
	if (p->full_size_known == false)
		return false;

	std::sort(p->fragments.begin(), p->fragments.end(),
		[](const auto & a, const auto & b) {
			return a.first < b.first;
		});

	uint16_t prev_end = 0;
	for(auto & fragment: p->fragments) {
		if (fragment.first != prev_end)  // this will "fail" for duplicate packets
			return false;
		prev_end = fragment.first + fragment.second;
	}

	return true;
}

// Ethernet -> IP4
void run_in(shm_message_queue *const shm, const std::pair<addr_ip4, int> & listen_addr,
            const std::map<uint8_t, std::string> & mappings_in, const std::string & icmp_error_name)
{
	std::map<uint64_t, packet> packets;
	std::mutex packets_lock;

	while(!stop_flag) {
		shm_message_queue::message *m = shm->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_any, { });
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

		if (pl_len < 20) {
			DOLOG(logger::ll_debug, "IP4 payload < 20 bytes");
			free(m);
			continue;
		}

		addr_ip4 ip4_src(&pl[12], 4);
		addr_ip4 ip4_dst(&pl[16], 4);  // me

		int header_size = (pl[0] & 15) * 4;
		int ip_size     = (pl[2] << 8) | pl[3];
		int protocol    = pl[9];
		int flags       = pl[6] >> 5;

		auto it = mappings_in.find(protocol);

		if (int version = pl[0] >> 4; version != 0x04) {
			DOLOG(logger::ll_debug, "Not an IP4 packet");
		}
		else if (ip4_dst != listen_addr.first) {
			DOLOG(logger::ll_debug, "%s is not for this instance", ip4_dst.to_str('.', false).c_str());
		}
		else if (header_size > ip_size) {
			DOLOG(logger::ll_debug, "Invalid IP4 header size");
			send_icmp_error(shm, icmp_error_name, 12, 2, { pl, pl_len }, ip4_src, ip4_dst);
		}
		else if (ip_size > ssize_t(pl_len)) {
			DOLOG(logger::ll_debug, "Invalid IP4 payload size");
			send_icmp_error(shm, icmp_error_name, 12, 2, { pl, pl_len }, ip4_src, ip4_dst);
		}
		else if (pl[8] == 0) {  // TTL exceeded?
			DOLOG(logger::ll_debug, "TTL exceeded");
			send_icmp_error(shm, icmp_error_name, 11, 0, { pl, pl_len }, ip4_src, ip4_dst);
		}
		else if (it == mappings_in.end()) {
			DOLOG(logger::ll_debug, "Protocol %d not known", protocol);
			send_icmp_error(shm, icmp_error_name, 3, 2, { pl, pl_len }, ip4_src, ip4_dst);
		}
		else {
			DOLOG(logger::ll_debug, "IP4 packet (IN) from %s to %s put in SHM %s for processing",
				ip4_src.to_str('.', false).c_str(),
				ip4_dst.to_str('.', false).c_str(),
				it->second.c_str());

			uint16_t checksum = ip_checksum(reinterpret_cast<const uint16_t *>(&pl[0]), header_size / 2);
			if (checksum != 0x0000) {
				DOLOG(logger::ll_debug, "IP4 packet has invalid checksum");
				free(m);
				continue;
			}

			shm_message_queue::message *wrapped = nullptr;

			size_t   pl_without_header_len = ip_size - header_size;

			uint16_t id     = (pl[4] << 8) | pl[5];

			uint16_t offset = (((pl[6] & 31) << 8) | pl[7]) * 8;
			// fragment?
			if (offset > 0 || (flags & 1)) {
				uint64_t frag_session = calc_session_id(ip4_src, ip4_dst, protocol, id);
				DOLOG(logger::ll_warning, "Fragmented packet, id: %x", frag_session);

				// store in fragment-store
				std::unique_lock<std::mutex> lck(packets_lock);
				auto it = packets.find(frag_session);
				if (it == packets.end()) {
					packet p;
					p.data            = nullptr;
					p.len             = 0;
					p.full_size_known = false;
					it = packets.insert({ frag_session, p }).first;
				}

				size_t current_fragment_end = offset + pl_without_header_len;
				if (current_fragment_end > it->second.len) {
					it->second.data = reinterpret_cast<uint8_t *>(realloc(it->second.data, current_fragment_end));
					it->second.len  = current_fragment_end;
				}
				memcpy(&it->second.data[offset], &pl[header_size], pl_without_header_len);
				// keep track of what segments arrived to be able to see if everything arrived
				it->second.fragments.push_back({ offset, pl_without_header_len });

				if ((flags & 1) == 0)
					it->second.full_size_known = true;

				if (is_complete(&it->second)) {
					DOLOG(logger::ll_warning, "Packet with id %x is complete, full size: %zu bytes",
							frag_session, it->second.len);
					wrapped = wrap_message_up(
						ip_size,        pl,  // use the re-assembled here?
						4,             &pl[12],
						4,             &pl[16],
						it->second.len, it->second.data,
						{ });

					packets.erase(it);
				}
			}
			else {
				wrapped = wrap_message_up(
						ip_size,                pl,
						4,                     &pl[12],
						4,                     &pl[16],
						pl_without_header_len, &pl[header_size],
						{ });
			}

			if (wrapped) {
				if (shm->send_message(it->second, wrapped, false) == false)
					DOLOG(logger::ll_warning, "Cannot send to %s", it->second.c_str());

				free(wrapped);
			}
		}

		free(m);
	}
}

std::optional<uint64_t> start_resolve_by_ip4(shm_message_queue *const shm_resolver_replies, const std::string & resolver_name, const addr_ip4 & a)
{
	const std::string msg = std::format("search-mac={0}", a.to_str('.', false));

	shm_message_queue::message *res_req_msg = allocate_shm_message(msg.size());
	res_req_msg->type = shm_message_queue::msg_new;
	res_req_msg->size = msg.size();
	memcpy(res_req_msg->data, msg.c_str(), msg.size());
	if (shm_resolver_replies->send_message(resolver_name, res_req_msg, false)) {
		uint64_t msg_nr = res_req_msg->msg_nr;
		free(res_req_msg);
		return msg_nr;
	}

	free(res_req_msg);
	return { };
}

// any messages from something sent to this server to be sent out via its parent?
// IP4 -> Ethernet
void run_out(shm_message_queue *const shm, const std::pair<addr_ip4, int> & listen_addr,
	     const addr_ip4 & default_gw_addr,
             const std::map<std::string, uint8_t> & mappings_out, const std::string & link_name,
	     shm_message_queue *const shm_resolver_replies, const std::string & resolver_name,
	     shm_message_queue *const shm_upper_in)
{
	struct pending_msg {
		uint64_t ts;  // when it was placed in the queue, microseconds since epoch
		shm_message_queue::message *queued_msg;
		uint64_t                from_nr;
		std::optional<addr_mac> from;
		uint64_t                to_nr;
		std::optional<addr_mac> to;
	};

	uint32_t masks[32] { };
	uint32_t mask_value = 0;
	for(int i=0; i<32; i++) {
		masks[i] = mask_value;
		mask_value >>= 1;
		mask_value |= 0x8000'0000;
	}

	const uint8_t *listen_addr_bytes = listen_addr.first.get();
	const uint32_t listen_addr_word  = (listen_addr_bytes[0] << 24) | (listen_addr_bytes[1] << 16) |
		(listen_addr_bytes[2] << 8) | listen_addr_bytes[3];
	const uint32_t listen_cidr_word  = listen_addr_word & masks[listen_addr.second];

	std::map<uint64_t, pending_msg *> pending_messages;
	std::mutex pending_messages_lock;

	// cleaner thread
	std::thread th_cleaner([&] {
		int sleep_count = 0;
		while(!stop_flag) {
			if (++sleep_count < 10) {
				usleep(100'000);
				continue;
			}
			sleep_count = 0;

			std::set<uint64_t> erase_keys;

			uint64_t now = get_us();
			std::unique_lock<std::mutex> lck(pending_messages_lock);
			for(auto & it: pending_messages) {
				if (erase_keys.find(it.first) != erase_keys.end())
					continue;

				if (now - it.second->ts >= 2'500'000) {
					free(it.second->queued_msg);
					erase_keys.insert(it.second->from_nr);
					erase_keys.insert(it.second->to_nr  );
				}
			}

			if (erase_keys.empty() == false)
				DOLOG(logger::ll_debug, "Forgetting %zu request-records", erase_keys.size());

			for(auto & key: erase_keys)
				pending_messages.erase(key);
		}
	});

	// go through the packets that are queued for send and see
	// if all data is available now (meaning: the from/to MAC-
	// addresses)
	std::thread th_sender([&] {
		while(!stop_flag) {
			shm_message_queue::message *resolve_result = shm_resolver_replies->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_reply, { });
			if (!resolve_result)
				continue;

			// find record for this parameter
			std::unique_lock<std::mutex> lck(pending_messages_lock);
			auto it = pending_messages.find(resolve_result->msg_nr);
			if (it == pending_messages.end()) {
				DOLOG(logger::ll_error, "Request-record for message from \"%s\" cannot be found", resolve_result->sender);
				free(resolve_result);
				continue;
			}

			// fill in missing part
			std::string resolve_result_str(reinterpret_cast<const char *>(resolve_result->data), resolve_result->size);
			auto is = resolve_result_str.find("=mac:");
			// should verify IP4 address
			if (is == std::string::npos) {
				DOLOG(logger::ll_error, "Request-record contains invalid answer: \"%s\"", resolve_result_str.c_str());
				free(resolve_result);
				continue;
			}
			addr_mac resolve_result_addr(resolve_result_str.substr(is + 5), ":", true);

			auto *pending_msg_meta = it->second;
			if (pending_msg_meta->from_nr == it->first)
				pending_msg_meta->from = resolve_result_addr;
			else if (pending_msg_meta->to_nr == it->first)
				pending_msg_meta->to   = resolve_result_addr;
			else {
				DOLOG(logger::ll_error, "Unexpected message number %" PRIu64 ", expected either %" PRIu64 " or %" PRIu64, it->first, pending_msg_meta->from_nr, pending_msg_meta->to_nr);
				pending_messages.erase(it);
				free(resolve_result);
				continue;
			}

			// if either one has not been filled in, continue
			if (pending_msg_meta->from.has_value() == false ||
			    pending_msg_meta->to  .has_value() == false) {
				pending_messages.erase(it);  // erase one of the pending msg meta-records
				free(resolve_result);
				continue;
			}

			// encapsulate, send to link_name
			auto protocol_it = mappings_out.find(pending_msg_meta->queued_msg->sender);
			if (protocol_it == mappings_out.end())
				DOLOG(logger::ll_error, "Message from \"%s\" cannot be mapped", pending_msg_meta->queued_msg->sender);
			else {
				int protocol = protocol_it->second;

				size_t         from_len     = 0;
				size_t         to_len       = 0;
				size_t         pl_len       = 0;
				const uint8_t *from         = nullptr;
				const uint8_t *to           = nullptr;
				const uint8_t *pl           = nullptr;
				if (unwrap_message_down(pending_msg_meta->queued_msg, &from_len, &from, &to_len, &to, &pl_len, &pl) == false) {
					DOLOG(logger::ll_error, "Corrupt message in shared memory segment!");
					// goto should be an option here
				}
				else {
					size_t   complete_msg_size = pl_len + 20;
					uint8_t *complete_msg      = new uint8_t[complete_msg_size]();
					uint8_t *header            = complete_msg;
					// IP4 header
					header[0] = (4 << 4) | 5;
					header[2] = complete_msg_size >> 8;
					header[3] = complete_msg_size;
					header[8] = 63;  // TTL
					header[9] = protocol;
					// checksum @ (10, 11)
					memcpy(&header[12], from, 4);
					memcpy(&header[16], to,   4);
					memcpy(&complete_msg[20], pl, pl_len);

					uint16_t checksum = ip_checksum(reinterpret_cast<const uint16_t *>(&header[0]), 10);
					header[10] = checksum >> 8;
					header[11] = checksum;

					auto *wrapped = wrap_message_down(
							pending_msg_meta->from.value().length(), pending_msg_meta->from.value().get(),
							pending_msg_meta->to  .value().length(), pending_msg_meta->to  .value().get(),
							complete_msg_size, complete_msg,
							{ });

					// SEND via shm[link_name] 
					if (shm->send_message(link_name, wrapped, false) == false)
						DOLOG(logger::ll_debug, "Failed to place packet in shared memory");

					free(wrapped);

					delete [] complete_msg;
				}
			}

			free(pending_msg_meta->queued_msg);
			delete pending_msg_meta;
			pending_messages.erase(it);  // should be the last pending msg meta-record
			free(resolve_result);
		}
	});

	while(!stop_flag) {
		shm_message_queue::message *m = shm_upper_in->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_any, { });
		if (!m)
			continue;

		size_t         from_len = 0;
		size_t         to_len   = 0;
		size_t         pl_len   = 0;
		const uint8_t *from     = nullptr;
		const uint8_t *to       = nullptr;
		const uint8_t *pl       = nullptr;
		if (unwrap_message_down(m, &from_len, &from, &to_len, &to, &pl_len, &pl) == false) {
			DOLOG(logger::ll_error, "Corrupt message in shared memory segment!");
			free(m);
			continue;
		}

		if (from_len != 4 || to_len != 4) {
			DOLOG(logger::ll_warning, "Unexpected from (%zu: %s)/to (%zu: %s) address size(s)",
					from_len, dump(from, from_len).c_str(),
					to_len,   dump(to,    to_len ).c_str());
			free(m);
			continue;
		}

		// start resolve of from/to MAC addresses
		auto from_msg_nr = start_resolve_by_ip4(shm_resolver_replies, resolver_name, addr_ip4(from, 4));

		uint32_t to_word = (to[0] << 24) | (to[1] << 16) | (to[2] << 8) | to[3];
		addr_ip4 via     = addr_ip4(to, 4);
		if ((to_word & masks[listen_addr.second]) != listen_cidr_word) {
			DOLOG(logger::ll_debug, "Route %s via %s", via.to_str('.', false).c_str(), default_gw_addr.to_str('.', false).c_str());
			via = default_gw_addr;
		}

		auto to_msg_nr   = start_resolve_by_ip4(shm_resolver_replies, resolver_name, via);

		// if the resolve-actions-start succeeded, queue the
		// message for fill-in & send
		if (from_msg_nr.has_value() && to_msg_nr.has_value())
		{
			auto         now = get_us();
			pending_msg *pm  = new pending_msg { now, m, from_msg_nr.value(), { }, to_msg_nr.value(), { } };
			std::unique_lock<std::mutex> lck(pending_messages_lock);
			pending_messages.insert({ from_msg_nr.value(), pm });
			pending_messages.insert({ to_msg_nr  .value(), pm });
			// NO free of 'm'! it is 'moved' to pending_messages!
			DOLOG(logger::ll_debug, "IP4 packet (OUT) from %s to %s queued for processing",
					addr(from, from_len).to_str('.', false).c_str(),
					addr(to,   to_len  ).to_str('.', false).c_str());
		}
		else {
			DOLOG(logger::ll_warning, "Could not start resolve of either from and/or to");
			free(m);
		}
	}

	th_sender .join();
	th_cleaner.join();
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
         const addr_ip4 & default_gw_addr,
         const std::map<uint8_t, std::string> & mappings_in,
         const std::map<std::string, uint8_t> & mappings_out,
	 const std::string & icmp_error_name, const std::string & link_name,
	 shm_message_queue *const shm_resolver_replies, const std::string & resolver_name,
	 shm_message_queue *const upper_in)
{
	std::thread rx([&] { run_in (shm, listen_addr, mappings_in,  icmp_error_name); });
	std::thread tx([&] { run_out(shm, listen_addr, default_gw_addr, mappings_out, link_name, shm_resolver_replies, resolver_name, upper_in); });
        std::thread announce([shm, announce_ip4_addr, listen_addr] { announcer(shm, announce_ip4_addr, listen_addr.first); });
        announce.join();
        tx.join();
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
		uint16_t    k   = std::stoi(col + 1);
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
	std::string lower_in_name = iniparser_getstring(d, "global:lower-in-name",  "");
	if (lower_in_name.empty()) {
		fprintf(stderr, "\"lower-in-name\" under \"global\" missing\n");
		return 1;
	}
	std::string upper_in_name = iniparser_getstring(d, "global:upper-in-name",  "");
	if (upper_in_name.empty()) {
		fprintf(stderr, "\"upper-in-name\" under \"global\" missing\n");
		return 1;
	}
	std::string out_name = iniparser_getstring(d, "global:out-name",  "");
	if (out_name.empty()) {
		fprintf(stderr, "\"out-name\" under \"global\" missing\n");
		return 1;
	}
	std::string icmp_error_name = iniparser_getstring(d, "specific:icmp-error-name",  "");
	if (icmp_error_name.empty()) {
		fprintf(stderr, "\"icmp-error-name\" under \"specific\" missing\n");
		return 1;
	}
	std::string resolver_name = iniparser_getstring(d, "specific:resolver-name",  "");
	if (resolver_name.empty()) {
		fprintf(stderr, "\"resolver-name\" under \"specific\" missing\n");
		return 1;
	}
	std::string resolver_replies = iniparser_getstring(d, "specific:resolver-replies",  "");
	if (resolver_replies.empty()) {
		fprintf(stderr, "\"resolver-replies\" under \"specific\" missing\n");
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
	std::string default_gw_addr_str = iniparser_getstring(d, "specific:default-gw",  "");
	if (default_gw_addr_str.empty()) {
		fprintf(stderr, "\"default-gw\" under \"specific\" missing\n");
		return 1;
	}
	addr_ip4 default_gw_addr(default_gw_addr_str, ".", false);
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

	shm_message_queue shm(lower_in_name, msg_queue_size);
	if (shm.begin() == false) {
		fprintf(stderr, "Cannot initialize shared memory segment \"%s\"\n", lower_in_name.c_str());
		return 1;
	}

	shm_message_queue shm_resolver_replies(resolver_replies, msg_queue_size);
	if (shm_resolver_replies.begin() == false) {
		fprintf(stderr, "Cannot initialize shared memory segment \"%s\"\n", resolver_replies.c_str());
		return 1;
	}

	shm_message_queue shm_upper_in(upper_in_name, msg_queue_size);
	if (shm_upper_in.begin() == false) {
		fprintf(stderr, "Cannot initialize shared memory segment \"%s\"\n", upper_in_name.c_str());
		return 1;
	}

	run(&shm, announce_ip4_addr, { listen_addr, cidr }, default_gw_addr, mappings_in, mappings_out,
            icmp_error_name, out_name, &shm_resolver_replies, resolver_name, &shm_upper_in);

	return 0;
}
