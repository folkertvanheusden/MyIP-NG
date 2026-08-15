#include <atomic>
#include <cassert>
#include <cerrno>
#include <cinttypes>
#include <condition_variable>
#include <csignal>
#include <map>
#include <mutex>
#include <thread>
#include <iniparser/iniparser.h>
#include <sys/random.h>

extern "C" {
#include "3dparty/SipHash/siphash.h"
}
#include "common.h"
#include "utils/addresses.h"
#include "utils/checksum.h"
#include "utils/gen.h"
#include "utils/log.h"
#include "utils/net.h"
#include "utils/random.h"
#include "utils/shm.h"
#include "utils/shm_message.h"
#include "utils/stoi.h"
#include "utils/time.h"


#define FLAG_CWR (1 << 7)
#define FLAG_ECE (1 << 6)
#define FLAG_URG (1 << 5)
#define FLAG_ACK (1 << 4)
#define FLAG_PSH (1 << 3)
#define FLAG_RST (1 << 2)
#define FLAG_SYN (1 << 1)
#define FLAG_FIN (1 << 0)

enum tcp_state_t { listen, syn_sent, syn_received, established, fin_wait_1, fin_wait_2, close_wait, closing, last_ack, time_wait, closed };

struct session_t {
	bool        is_client;
	char        shm_peer[max_id_length];  // only valid for is_client == true

	tcp_state_t state;
	uint32_t    start_local_seq;
	uint32_t    start_peer_seq;
	uint32_t    local_seq;
	uint32_t    peer_seq;
	uint16_t    local_window_size;
	uint16_t    peer_window_size;

	addr        local_addr;
	uint16_t    local_port;
	addr        peer_addr;
	uint16_t    peer_port;

	std::mutex  lock;
};

std::atomic_bool stop_flag { false };

std::string seq_delta_lcl(const session_t *const s, const std::optional<uint32_t> & current = { })
{
	uint32_t use = current.has_value() ? current.value() : s->local_seq;

	// this will fail after 2^32 bytes
	if (use < s->start_local_seq)
		return std::format("{}", UINT32_MAX - s->start_local_seq + use);

	return std::format("{}", use - s->start_local_seq);
}

std::string seq_delta_peer(const session_t *const s, const std::optional<uint32_t> & current = { })
{
	uint32_t use = current.has_value() ? current.value() : s->peer_seq;

	// this will fail after 2^32 bytes
	if (use < s->start_peer_seq)
		return std::format("{}", UINT32_MAX - s->start_peer_seq + use);

	return std::format("{}", use - s->start_peer_seq);
}

void sig_handler(int sig)
{
	stop_flag = true;
}

std::string flags_to_str(const int flags)
{
	std::string out;

	if (flags & FLAG_CWR)
		out += "CWR,";
	if (flags & FLAG_ECE)
		out += "ECE,";
	if (flags & FLAG_URG)
		out += "URG,";
	if (flags & FLAG_ACK)
		out += "ACK,";
	if (flags & FLAG_PSH)
		out += "PSH,";
	if (flags & FLAG_RST)
		out += "RST,";
	if (flags & FLAG_SYN)
		out += "SYN,";
	if (flags & FLAG_FIN)
		out += "FIN,";

	if (out.empty() == false)
		out.erase(out.size() - 1);

	return out;
}

void send_icmp_error(shm_message_queue *const shm, const std::string & icmp_error_name, const int type, const int code, const std::pair<const uint8_t *, size_t> & payload, const addr_ip4 & to, const addr_ip4 & me)
{
	uint8_t extra_data[2] { };
	extra_data[0] = type;
	extra_data[1] = code;

	auto *wrapped = wrap_message_up(
			payload.second, payload.first,
			me.length(), me.get(),
			to.length(), to.get(),
			sizeof extra_data, extra_data,
			{ });

	if (shm->send_message(icmp_error_name, wrapped, false) == false)
		DOLOG(logger::ll_warning, "ERR) Cannot send ICMP message");
	else
		DOLOG(logger::ll_debug, "INF) ICMP message type %d code %d queued", type, code);

	free(wrapped);
}

static uint64_t calc_session_id(const uint16_t src_port, const uint16_t dst_port, const addr & from, const addr & to)
{
	size_t   from_len = from.length();

	size_t   session_id_buffer_len = 2 + 2 + from_len + to.length();
	uint8_t *session_id_buffer     = new uint8_t[session_id_buffer_len]();

	*reinterpret_cast<uint16_t *>(&session_id_buffer[0]) = src_port;
	*reinterpret_cast<uint16_t *>(&session_id_buffer[2]) = dst_port;
	from.get(&session_id_buffer[4]);
	to  .get(&session_id_buffer[4 + from_len]);

	auto rc = fletcher64(session_id_buffer, session_id_buffer_len);
	delete [] session_id_buffer;

	return rc;
}

uint32_t my_syn_cookie(const uint64_t session_id, const uint8_t syn_cookie_salt[16])
{
	uint8_t  buffer[8 + 1];
	memcpy(&buffer[0], &session_id, sizeof session_id);
	time_t   now = time(nullptr);
	uint32_t t   = (now >> 6) & 31;
	buffer[8] = t;

	uint32_t sip_out[2] { };
	siphash(buffer, sizeof buffer, syn_cookie_salt, reinterpret_cast<uint8_t *>(sip_out), sizeof sip_out);

	uint32_t s = sip_out[0] ^ sip_out[1];  // fold hash in half
	return (s & 0xFFFFFFE0) | t;
}

bool send_tcp_packet(shm_message_queue *const shm, const std::string & down,
		const addr & from, const addr & to,
		const int src_port, const int dst_port, const uint32_t seq_nr, const uint32_t ack_nr,
		const int flags, const uint16_t window_size, const std::pair<const uint8_t *, size_t> & payload)
{
	size_t   packet_length = 20 + payload.second;
	uint8_t *packet        = new uint8_t[packet_length]();

	put_uint16(&packet[0], src_port);
	put_uint16(&packet[2], dst_port);
	put_uint32(&packet[4], seq_nr  );
	put_uint32(&packet[8], ack_nr  );
	packet[12] = 5 << 4;  // header size
	packet[13] = flags;
	put_uint16(&packet[14], window_size);
	if (payload.second)
		memcpy(&packet[20], payload.first, payload.second);

	uint16_t checksum = tcp_udp_checksum(from, to, packet, packet_length, 6);
	put_uint16(&packet[16], checksum);

	auto *wrapped = wrap_message_down(
			from.length(), from.get(),
			to.length(),   to.get(),
			packet_length, packet,
			{ });

	bool rc = shm->send_message(down, wrapped, false);
	if (rc == false)
		DOLOG(logger::ll_warning, "ERR) Cannot send to %s", down.c_str());

	free(wrapped);

	delete [] packet;

	return rc;
}

// ip -> tcp
void run_in(shm_message_queue *const shm, const std::map<uint16_t, std::string> & mappings_in, const std::string & icmp_error_name,
	    const std::string & out_name,
	    std::map<uint64_t, session_t *> *const sessions, std::mutex & sessions_lock,
	    const uint8_t syn_cookie_salt[16])
{
	set_thread_name("run_in");

        DOLOG(logger::ll_debug, "INF) waiting for packets (IP->TCP) on shm %s", shm->get_local_identifier().c_str());

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
                        DOLOG(logger::ll_error, "ERR) Corrupt message in shared memory segment!");
                        free(m);
                        continue;
                }

		if (pl_len < 20) {
			free(m);
			DOLOG(logger::ll_debug, "ERR) TCP packet too small");
			continue;
		}

		addr_ip4 a_from(from, from_len);
		addr_ip4 a_to  (to  , to_len  );

		// check checksum
		uint16_t checksum = tcp_udp_checksum(a_from, a_to, pl, pl_len, 6);
		if (checksum != 0x0000) {
			DOLOG(logger::ll_debug, "ERR) TCP packet has incorrect checksum");
			free(m);
			continue;
		}

		uint16_t source_port      = get_uint16(&pl[0]);
		uint16_t destination_port = get_uint16(&pl[2]);
		uint64_t session_id       = calc_session_id(source_port, destination_port, a_from, a_to);
		int      header_size      = (pl[12] >> 4) * 4;
		int      flags            =  pl[13];
		uint16_t window_size      = get_uint16(&pl[14]);
		uint32_t peer_seq_nr      = get_uint32(&pl[ 4]);
		uint32_t my_seq_nr        = get_uint32(&pl[ 8]);
		int      tcp_pl_size      = pl_len - header_size;

		if (header_size > pl_len) {
			free(m);
			DOLOG(logger::ll_debug, "ERR) TCP header too large");
			continue;
		}

		DOLOG(logger::ll_debug, "INF) TCP packet from %d to %d, session id: %" PRIx64 ", flags: %s, pl size: %d",
				source_port, destination_port, session_id,
				flags_to_str(flags).c_str(),
				tcp_pl_size);

		session_t *session = nullptr;
		{
			std::unique_lock<std::mutex> lck(sessions_lock);
			auto it = sessions->find(session_id);
			if (it != sessions->end()) {
				session = it->second;
				session->lock.lock();
			}
		}

		if (session) {
			DOLOG(logger::ll_debug, "INF) TCP session %" PRIx64 ", local seq nr: %s, ack seq nr: %s",
					session_id, seq_delta_lcl(session).c_str(), seq_delta_lcl(session, my_seq_nr).c_str());
			DOLOG(logger::ll_debug, "INF) TCP session %" PRIx64 ", expected peer seq nr: %s, recv peer seq nr: %s",
					session_id, seq_delta_peer(session).c_str(), seq_delta_peer(session, peer_seq_nr).c_str());
		}

		bool invalid         = false;
		bool invalid_w_rst   = true;
		bool invalid_inc_ack = false;
		bool clean_session   = false;

		if (flags & FLAG_SYN) {
			invalid_inc_ack = true;
			// either a SYN/ACK for a server or a client (client sessions
			// always start with a session allocated)
			if (session) {
				if (session->is_client) {  // client? then this should be SYN/ACK
					if ((flags & FLAG_ACK) == 0) {
						DOLOG(logger::ll_debug, "INF) Received SYN for session %" PRIx64 " (client)", session_id);
						invalid = true;
					}
					else {
						if (session->state == established)
							DOLOG(logger::ll_debug, "WRN) Received SYN/ACK for session %" PRIx64 " (client, established state)", session_id);
						else {
							session->state = established;
							DOLOG(logger::ll_debug, "INF) Received SYN/ACK for session %" PRIx64 ", sending ACK", session_id);
							session->start_peer_seq = session->peer_seq = peer_seq_nr;
						}
						// send ACK
						session->peer_seq++;
						DOLOG(logger::ll_debug, "INF) TCP session %" PRIx64 ", local: %u, ack: %u", session->local_seq, session->peer_seq);
						if (send_tcp_packet(shm, out_name,
								a_to, a_from,  // swapped: reply
								destination_port, source_port,  // swapped: reply
								session->local_seq, session->peer_seq,
								FLAG_ACK, session->local_window_size, { nullptr, 0 }) == false)
						{
							clean_session = true;
							DOLOG(logger::ll_debug, "ERR) Could not send ACK for client session %" PRIx64, session_id);
						}
					}
				}
				else {
					DOLOG(logger::ll_debug, "ERR) Received SYN for session %" PRIx64 " in ESTABLISHED state -> RST", session_id);
					invalid = true;
				}
			}
			else {  // new session
				auto it = mappings_in.find(destination_port);
				if (it == mappings_in.end()) {
					DOLOG(logger::ll_debug, "ERR) No mapping for port %d", destination_port);
					invalid = true;
				}
				else if (flags & (FLAG_FIN | FLAG_RST | FLAG_PSH | FLAG_URG | FLAG_ACK)) {
					DOLOG(logger::ll_debug, "ERR) Invalid flags set (%s) combined with SYN in a new session -> RST", flags_to_str(flags).c_str());
					invalid = true;
					invalid_w_rst = !(flags & FLAG_RST);  // no RST if the flags already contain RST
				}
				else {
					uint32_t syn_cookie = my_syn_cookie(session_id, syn_cookie_salt);
					DOLOG(logger::ll_debug, "INF) Session %" PRIx64 " using SYN cookie %08x, acking to %08x",
							session_id, syn_cookie, peer_seq_nr);

					send_tcp_packet(shm, out_name,
							a_to, a_from,  // swapped: reply
							destination_port, source_port,  // swapped: reply
							syn_cookie, peer_seq_nr + 1,
							FLAG_SYN | FLAG_ACK, window_size, { nullptr, 0 });
				}
			}
		}
		else if (flags & FLAG_ACK) {
			if (session) {
				if (flags & FLAG_FIN) {
					session->local_seq++;
					send_tcp_packet(shm, out_name,
							a_to, a_from,  // swapped: reply
							destination_port, source_port,  // swapped: reply
							session->local_seq, peer_seq_nr + 1,
							FLAG_FIN | FLAG_ACK, window_size, { nullptr, 0 });

					// TODO handle half closed sessions

					clean_session = true;
				}
				else {
					// TODO
				}
			}
			else {  // start of new session
				uint32_t syn_cookie = my_syn_cookie(session_id, syn_cookie_salt) + 1;
				if (syn_cookie != my_seq_nr) {
					DOLOG(logger::ll_debug, "ERR) Invalid SYN-cookie %08x - expecting %08x", my_seq_nr, syn_cookie);
					send_tcp_packet(shm, out_name,
							a_to, a_from,  // swapped: reply
							destination_port, source_port,  // swapped: reply
							syn_cookie, peer_seq_nr + 1,
							FLAG_RST, window_size, { nullptr, 0 });
				}
				else {
					// allocate session
					session_t *new_session = new session_t;
					new_session->is_client  = false;
					new_session->state      = established;
					new_session->local_seq  = syn_cookie;
					new_session->local_addr = a_to;
					new_session->local_port = destination_port;
					new_session->peer_seq   = peer_seq_nr;
					new_session->peer_addr  = a_from;
					new_session->peer_port  = source_port;
					std::unique_lock<std::mutex> lck(sessions_lock);
					sessions->insert({ session_id, new_session });
				}
			}
		}
		else {
			DOLOG(logger::ll_debug, "ERR) Session %" PRIx64 " has an unexpected state", session_id);
		}

		// send data to other end (local shm peer)
		if (session != nullptr) {
			if (peer_seq_nr == session->peer_seq) {
				bool ok = true;
				if (tcp_pl_size > 0) {
					shm_message_queue::message *m_session = allocate_shm_message(tcp_pl_size + 8);
					m_session->type = shm_message_queue::msg_new;
					assert(sizeof(session_id) == 8);
					memcpy(&m_session->data[0], &session_id, sizeof session_id);
					memcpy(&m_session->data[8], &pl[header_size], tcp_pl_size);
					ok = shm->send_message(session->shm_peer, m_session, false);
					free(m_session);
				}

				if (ok) {
					DOLOG(logger::ll_debug, "INF) Session %" PRIx64 ", data sent to client", session_id);
					if (send_tcp_packet(shm, out_name,
							a_to, a_from,  // swapped: reply
							destination_port, source_port,  // swapped: reply
							session->local_seq, session->peer_seq + tcp_pl_size,
							FLAG_ACK, session->local_window_size, { nullptr, 0 })) {
						session->peer_seq += tcp_pl_size;
					}
					else
					{
						clean_session = true;
						DOLOG(logger::ll_debug, "ERR) Could not ACK data for session %" PRIx64, session_id);
					}
				}
				else {
					DOLOG(logger::ll_debug, "ERR) Cannot send to peer shm, session %" PRIx64, session_id);
					// do nothing, tcp-peer should retry eventually
				}
			}
			else if (peer_seq_nr < session->peer_seq) {
				DOLOG(logger::ll_debug, "INF) Peer resends packet for session %" PRIx64, session_id);

				if (send_tcp_packet(shm, out_name,
							a_to, a_from,  // swapped: reply
							destination_port, source_port,  // swapped: reply
							session->local_seq, session->peer_seq,
							FLAG_ACK, session->local_window_size, { nullptr, 0 }) == false) {
					clean_session = true;
					DOLOG(logger::ll_debug, "ERR) Could not ACK data for session %" PRIx64, session_id);
				}
			}
			else {
				DOLOG(logger::ll_debug, "ERR) TCP out of order packet, expecting seq %u, got %u for session %" PRIx64, session->peer_seq, peer_seq_nr, session_id);
			}
		}
		else {
			DOLOG(logger::ll_debug, "WRN) Packet for an not known session with id %" PRIx64, session_id);
		}

		if (invalid || clean_session) {
			if (invalid && invalid_w_rst) {
				send_tcp_packet(shm, out_name,
						a_to, a_from,  // swapped: reply
						destination_port, source_port,  // swapped: reply
						session ? session->local_seq : 0, session ? peer_seq_nr + invalid_inc_ack : 0,
						FLAG_RST, window_size, { nullptr, 0 });
			}

			if (session) {
				std::unique_lock<std::mutex> lck(sessions_lock);
				// remove from the map
				sessions->erase(session_id);
				// now it can be unlocked and deleted
				session->lock.unlock();
				delete session;
			}
		}
		else {
			if (session)
				session->lock.unlock();
		}

		free(m);
	}
}

// tcp -> ip
void run_out(shm_message_queue *const shm, const std::string & out_name, shm_message_queue *const shm_out,
	    std::map<uint64_t, session_t *> *const sessions, std::mutex & sessions_lock)
{
	set_thread_name("run_out");

        DOLOG(logger::ll_debug, "INF) waiting for packets (client->TCP) on shm %s", shm->get_local_identifier().c_str());
        DOLOG(logger::ll_debug, "INF) sending packets to %s (TCP->IP) via shm-name %s", out_name.c_str(), shm_out->get_local_identifier().c_str());

	std::map<uint64_t, std::vector<shm_message_queue::message *> > payloads;
	std::mutex              payload_lock;
	std::condition_variable payload_cv;

	std::thread sender([&] {
		set_thread_name("run_out::sender");
		std::unique_lock<std::mutex> lck(payload_lock);

		while(!stop_flag) {
			if (payload_cv.wait_for(lck, std::chrono::milliseconds(SLEEP_INTERVAL_MS)) == std::cv_status::timeout)
				continue;

			std::vector<uint64_t> forget;

			for(auto & target: payloads) {
				session_t *session = nullptr;
				{
					std::unique_lock<std::mutex> lck(sessions_lock);
					auto it = sessions->find(target.first);
					if (it != sessions->end()) {
						session = it->second;
						session->lock.lock();
					}
				}

				if (session == nullptr) {
					DOLOG(logger::ll_warning, "WRN) TCP session not found for %" PRIx64, target.first);
					for(auto & item: target.second)
						free(item);
					forget.push_back(target.first);
					continue;
				}

				if (session)
					DOLOG(logger::ll_debug, "INF) TCP session %" PRIx64 ", local seq nr: %s",
							target.first, seq_delta_lcl(session).c_str());


				int n = 0;
				while(target.second.empty() == false) {
					auto item    = target.second.front();
					int  pl_size = item->size - 8;

					// TODO handle peer window size

					DOLOG(logger::ll_debug, "INF) TCP sent packet to %s for session %" PRIx64, out_name.c_str(), target.first);
					if (send_tcp_packet(shm_out, out_name,
								session->local_addr, session->peer_addr,
								session->local_port, session->peer_port,
								session->local_seq,  session->peer_seq,
								0, session->local_window_size, { &item->data[8], pl_size }) == false) {
						break;
					}

					session->local_seq += pl_size;

					free(item);
					target.second.erase(target.second.begin() + 0);
					n++;
				}

				session->lock.unlock();

				if (n)
					DOLOG(logger::ll_debug, "INF) TCP sent %d item(s) for session %" PRIx64, n, target.first);

				if (target.second.empty()) {
					DOLOG(logger::ll_debug, "INF) TCP queue for session %" PRIx64 " is empty", target.first);
					forget.push_back(target.first);
				}
			}

			for(auto & id: forget)
				payloads.erase(id);
		}
	});

	while(!stop_flag) {
		shm_message_queue::message *m = shm->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_new, { });
		if (!m)
			continue;

		if (m->size <= 8) {
			DOLOG(logger::ll_error, "ERR) TCP payload message too short");
			free(m);
			continue;
		}

		// unwrap
		uint64_t session_id = 0;
		memcpy(&session_id, m->data, 8);

		DOLOG(logger::ll_debug, "INF) TCP outbound for %" PRIx64 " received", session_id);

		// TODO max size & session time out

		{
			std::unique_lock<std::mutex> lck(payload_lock);
			auto it = payloads.find(session_id);  // TODO replace by insert + check afterwards
			if (it == payloads.end())
				it = payloads.insert({ session_id, { } }).first;
			it->second.push_back(m);
			payload_cv.notify_all();
		}
	}

	sender.join();
}

void run_meta(shm_message_queue *const shm, const std::string & out_name,
	      const addr & from_addr,
	      shm_message_queue *const shm_meta,
	      std::map<uint64_t, session_t *> *const sessions, std::mutex & sessions_lock)
{
	set_thread_name("run_meta");

	// map of local port and session-id
	// should also include addr in key
	std::map<uint16_t, uint64_t> local_allocated_ports;

	while(!stop_flag) {
		shm_message_queue::message *m = shm_meta->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_new, { });
		if (!m)
			continue;

		std::string kv(reinterpret_cast<const char *>(m->data), m->size);
		auto lines = split(kv, "\n");
		if (lines.size() < 2) {
			DOLOG(logger::ll_error, "ERR) TCP meta message missing data");
			free(m);
			continue;
		}

		enum { open, close } action = close;
		std::optional<uint64_t>    session_id;
		std::optional<addr>        dst_addr;
		std::optional<uint16_t>    dst_port;
		std::optional<std::string> shm_data_address;

		bool invalid = false;
		for(auto & line: lines) {
			DOLOG(logger::ll_debug, "INF) Received cfg item: \"%s\" from %s", line.c_str(), m->sender);
			auto parts = split(line, "=");
			if (parts.size() != 2) {
				DOLOG(logger::ll_error, "ERR) TCP meta message line invalid (missing either value or key: \"%s\")", line.c_str());
				invalid = true;
				break;
			}

			if (parts[0] == "action") {
				if (parts[1] == "open")
					action = open;
				else if (parts[1] == "close")
					action = close;
				else {
					DOLOG(logger::ll_error, "ERR) TCP meta: invalid action \"%s\"", parts[1].c_str());
					invalid = true;
					break;
				}
			}
			else if (parts[0] == "session-id") {
				session_id = my_stoi_hex(parts[1]);
			}
			else if (parts[0] == "dst-port") {
				dst_port = my_stoi_dec(parts[1]);
			}
			else if (parts[0] == "dst-addr-ip4") {
				dst_addr = addr(parts[1], ".", false);
			}
			else if (parts[0] == "shm-data-address") {
				shm_data_address = parts[1];
			}
			else {
				DOLOG(logger::ll_error, "ERR) TCP meta: invalid key \"%s\"", line.c_str());
				invalid = true;
				break;
			}
		}
		if (invalid) {
			free(m);
			continue;
		}

		if (action == open) {
			if (dst_port.has_value() && dst_addr.has_value() && shm_data_address.has_value()) {
				DOLOG(logger::ll_debug, "INF) Opening TCP session to [%s]:%d",
					dst_addr.value().to_str('.', false).c_str(), dst_port.value());
				bool     failed   = false;
				uint16_t src_port = 0;
				do {
					my_random(&src_port, sizeof src_port);
				}
				while(local_allocated_ports.find(src_port) != local_allocated_ports.end());

				if (failed == false) {
					uint64_t session_id = calc_session_id(dst_port.value(), src_port, dst_addr.value(), from_addr);
					session_t *new_session = new session_t;
					new_session->is_client         = true;
					memset(new_session->shm_peer, 0x00, max_id_length);
					memcpy(new_session->shm_peer, shm_data_address.value().c_str(), shm_data_address.value().size());
					new_session->state             = syn_sent;
					my_random(&new_session->local_seq, sizeof new_session->local_seq);
					new_session->start_local_seq   = new_session->local_seq;
					new_session->peer_seq          = 0;
					new_session->start_peer_seq    = 0;
					new_session->local_window_size = 512;
					new_session->local_addr        = from_addr;
					new_session->local_port        = src_port;
					new_session->peer_addr         = dst_addr.value();
					new_session->peer_port         = dst_port.value();

					// send SYN
					failed = !send_tcp_packet(shm, out_name,
							new_session->local_addr, new_session->peer_addr,
							new_session->local_port, new_session->peer_port,
							new_session->local_seq, new_session->peer_seq,
							FLAG_SYN, new_session->local_window_size, { nullptr, 0 });

					// return new session_id
					if (!failed) {
						const std::string reply = std::format("session-id={0:x}", session_id);
						shm_message_queue::message *m_rc = allocate_shm_message(reply.size());
						m_rc->type = shm_message_queue::msg_reply;
						memcpy(m_rc->data, reply.c_str(), m_rc->size);
						failed = !shm_meta->send_message(m->sender, m_rc, false);
						free(m_rc);

						new_session->local_seq++;
					}

					// if all went well:
					if (failed)
						delete new_session;
					else {
						local_allocated_ports.insert({ src_port, session_id });
						DOLOG(logger::ll_debug, "INF) New TCP client session with id %" PRIx64, session_id);

						std::unique_lock<std::mutex> lck(sessions_lock);
						sessions->insert({ session_id, new_session });
					}
				}
			}
			else {
				DOLOG(logger::ll_error, "ERR) TCP meta: open-action missing dst-port, dst-addr or shm-data-address");
			}
		}
		else if (action == close) {
			if (session_id.has_value()) {
				// send FIN, close session
				session_t *fin_session = nullptr;
				{
					std::unique_lock<std::mutex> lck(sessions_lock);
					auto it = sessions->find(session_id.value());
					if (it != sessions->end())
						fin_session = it->second;
				}

				if (fin_session != nullptr) {
					std::unique_lock<std::mutex> fin_lck(fin_session->lock);
					fin_session->local_seq++;

					auto ports_it = local_allocated_ports.find(fin_session->local_port);
					if (ports_it->second == session_id)
						local_allocated_ports.erase(ports_it);
					else
						DOLOG(logger::ll_error, "ERR) TCP meta: local port %u is mapped to an other session %x, not %x", ports_it->second, session_id);

					send_tcp_packet(shm, out_name,
							fin_session->local_addr, fin_session->peer_addr,
							fin_session->local_port, fin_session->peer_port,
							fin_session->local_seq,  fin_session->peer_seq + 1,
							FLAG_FIN, fin_session->local_window_size, { nullptr, 0 });

					std::unique_lock<std::mutex> lck(sessions_lock);
					sessions->erase(session_id.value());

					fin_session->lock.unlock();
					delete fin_session;
				}
				else {
					DOLOG(logger::ll_warning, "ERR) TCP meta: session %" PRIx64 " not in map", session_id);
				}
			}
			else {
				DOLOG(logger::ll_error, "ERR) TCP meta: close-action missing session-id");
			}
		}
		else {
			DOLOG(logger::ll_error, "ERR) TCP meta: internal error");
		}

		free(m);
	}
}

void run(shm_message_queue *const shm, const std::string & out_name,
	 const std::map<uint16_t, std::string> & mappings_in,
	 shm_message_queue *const shm_upper,
	 const std::string & icmp_error_name,
	 std::map<uint64_t, session_t *> *const sessions, std::mutex & sessions_lock,
	 const uint8_t syn_cookie_salt[16],
	 shm_message_queue *const shm_meta, const addr & local_addr)
{
	std::thread rx  ([&] { run_in  (shm, mappings_in, icmp_error_name, out_name, sessions, sessions_lock, syn_cookie_salt); });
	std::thread tx  ([&] { run_out (shm_upper, out_name, shm, sessions, sessions_lock); });
	std::thread meta([&] { run_meta(shm, out_name, local_addr, shm_meta, sessions, sessions_lock); });
	meta.join();
	tx  .join();
	rx  .join();
}

std::optional<uint64_t> send_meta_request(shm_message_queue *const shm_meta, const std::string & peer_name, const std::string & request)
{
        shm_message_queue::message *meta_request_msg = allocate_shm_message(request.size());
        meta_request_msg->type = shm_message_queue::msg_new;
        memcpy(meta_request_msg->data, request.c_str(), request.size());
        if (shm_meta->send_message(peer_name, meta_request_msg, false)) {
                uint64_t msg_nr = meta_request_msg->msg_nr;
                free(meta_request_msg);
                return msg_nr;
        }

        free(meta_request_msg);
        return { };
}

addr_ip4 cfg_runtime(shm_message_queue *const shm_meta, const std::string & meta_name_ip4_server)
{
	uint64_t last_tx = 0;
	uint64_t msg_nr  = 0;
	while(!stop_flag) {
		uint64_t now = get_us();

		if (now - last_tx > 2'000'000) {
			DOLOG(logger::ll_debug, "INF) Requesting IP4 address from \"%s\"", meta_name_ip4_server.c_str());

			auto temp = send_meta_request(shm_meta, meta_name_ip4_server, "get-ip4");
			if (temp.has_value()) {
				last_tx = now;
				msg_nr  = temp.value();
				DOLOG(logger::ll_debug, "INF) Message sent with id %" PRIu64, msg_nr);
			}
			else {
				usleep(SLEEP_INTERVAL_MS);
				continue;
			}
		}

		auto *reply = shm_meta->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_reply, msg_nr);
		if (reply) {
			std::string reply_str(reinterpret_cast<const char *>(reply->data), reply->size);
			DOLOG(logger::ll_debug, "INF) Reply received: \"%s\"", reply_str.c_str());
			free(reply);
			if (reply_str.substr(0, 4) == "ip4=")
				return addr(reply_str.substr(4), ".", false);
			DOLOG(logger::ll_warning, "ERR) Unexpected reply");
		}

		usleep(100'000);
	}

	return addr();
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

	DOLOG(logger::ll_info, "TCP server starting...");

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
	std::string name_upper = iniparser_getstring(d, "global:name-upper",  "");
	if (name_upper.empty()) {
		fprintf(stderr, "\"name-upper\" under \"global\" missing\n");
		return 1;
	}
	std::string name_meta = iniparser_getstring(d, "global:name-meta",  "");
	if (name_meta.empty()) {
		fprintf(stderr, "\"name-meta\" under \"global\" missing\n");
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
	std::string ip4_meta_name = iniparser_getstring(d, "global:ip4-meta-name",  "");
	if (ip4_meta_name.empty()) {
		fprintf(stderr, "\"ip4-meta-name\" under \"global\" missing\n");
		return 1;
	}
	int msg_queue_size_meta = iniparser_getint(d, "specific:meta-queue-size", 512);
	int msg_queue_size = iniparser_getint(d, "specific:msg-queue-size", 0);
	if (msg_queue_size == 0) {
		msg_queue_size = 16384;
		fprintf(stderr, "Using default msg queue size of %d bytes\n", msg_queue_size);
	}
	std::map<uint16_t, std::string> mappings_in;
	load_mappings_single(&mappings_in, d);
	iniparser_freedict(d);

	signal(SIGINT, sig_handler);

	shm_message_queue *shm = create_shm(name, msg_queue_size);
	if (shm == nullptr)
		return 1;

	shm_message_queue *shm_upper = create_shm(name_upper, msg_queue_size);
	if (shm_upper == nullptr)
		return 1;

	shm_message_queue *shm_meta = create_shm(name_meta, msg_queue_size_meta);
	if (shm_meta == nullptr)
		return 1;

	std::map<uint64_t, session_t *> sessions;
	std::mutex sessions_lock;

	uint8_t syn_cookie_salt[16];  // key size required by SipHAsh
	my_random(syn_cookie_salt, sizeof syn_cookie_salt);

	addr_ip4 send_addr = cfg_runtime(shm_meta, ip4_meta_name);
	if (stop_flag)
		return 1;

	run(shm, out_name, mappings_in, shm_upper, icmp_error_name, &sessions, sessions_lock, syn_cookie_salt, shm_meta, send_addr);

	delete shm_meta;
	delete shm_upper;
	delete shm;

	return 0;
}
