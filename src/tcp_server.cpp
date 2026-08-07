#include <atomic>
#include <cassert>
#include <cerrno>
#include <cinttypes>
#include <csignal>
#include <map>
#include <mutex>
#include <thread>
#include <iniparser/iniparser.h>
#include <sys/random.h>

extern "C" {
#include "3dparty/SipHash/siphash.h"
}
#include "utils/addresses.h"
#include "utils/checksum.h"
#include "utils/gen.h"
#include "utils/log.h"
#include "utils/net.h"
#include "utils/shm.h"
#include "utils/shm_message.h"


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
	tcp_state_t rx;
	uint32_t    local_seq;
	tcp_state_t tx;
	uint32_t    peer_seq;
	std::mutex  lock;
};

std::atomic_bool stop_flag { false };

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
		DOLOG(logger::ll_warning, "Cannot send ICMP message");
	else
		DOLOG(logger::ll_warning, "ICMP message type %d code %d queued", type, code);

	free(wrapped);
}

uint64_t calc_session_id(const uint8_t *const tcp_pl, const addr & from, const addr & to)
{
	size_t   from_len = from.length();

	size_t   session_id_buffer_len = 2 + 2 + from_len + to.length();
	uint8_t *session_id_buffer     = new uint8_t[session_id_buffer_len]();

	memcpy(session_id_buffer, tcp_pl, 4);  // source & destination ports
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

void send_tcp_packet(shm_message_queue *const shm, const std::string & down,
		const addr & from, const addr & to,
		const int src_port, const int dst_port, const uint32_t seq_nr, const uint32_t ack_nr,
		const int flags, const int window_size, const std::pair<const uint8_t *, size_t> & payload)
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

	if (shm->send_message(down, wrapped, false) == false)
		DOLOG(logger::ll_warning, "Cannot send to %s", down.c_str());

	free(wrapped);

	delete [] packet;
}

// ip -> tcp
void run_in(shm_message_queue *const shm, const std::map<uint16_t, std::string> & mappings_in, const std::string & icmp_error_name,
	    const std::string & out_name,
	    std::map<uint64_t, session_t *> *const sessions, std::mutex & sessions_lock,
	    const uint8_t syn_cookie_salt[16])
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

		if (pl_len < 20) {
			free(m);
			DOLOG(logger::ll_debug, "TCP packet too small");
			continue;
		}

		addr_ip4 a_from(from, from_len);
		addr_ip4 a_to  (to  , to_len  );

		// check checksum
		uint16_t checksum = tcp_udp_checksum(a_from, a_to, pl, pl_len, 6);
		if (checksum != 0x0000) {
			DOLOG(logger::ll_debug, "TCP packet has incorrect checksum");
			free(m);
			continue;
		}

		uint16_t source_port      = get_uint16(&pl[0]);
		uint16_t destination_port = get_uint16(&pl[2]);
		uint64_t session_id       = calc_session_id(pl, a_from, a_to);
		int      header_size      = (pl[12] >> 4) * 4;  // or >> 2
		int      flags            =  pl[13];
		int      window_size      = get_uint16(&pl[14]);
		uint32_t peer_seq_nr      = get_uint32(&pl[ 4]);
		uint32_t my_seq_nr        = get_uint32(&pl[ 8]);

		if (header_size > pl_len) {
			free(m);
			DOLOG(logger::ll_debug, "TCP header too large");
			continue;
		}

		DOLOG(logger::ll_debug, "TCP packet from %d to %d, session id: %" PRIx64 ", flags: %s",
				source_port, destination_port, session_id,
				flags_to_str(flags).c_str());

		session_t *session = nullptr;
		{
			std::unique_lock<std::mutex> lck(sessions_lock);
			auto it = sessions->find(session_id);
			if (it != sessions->end()) {
				session = it->second;
				session->lock.lock();
			}
		}

		bool invalid = false;
		bool invalid_w_rst = true;
		bool invalid_inc_ack = false;

		if (flags & FLAG_SYN) {
			invalid_inc_ack = true;
			if (session) {
				DOLOG(logger::ll_debug, "Received SYN for session %" PRIx64 " in ESTABLISHED state -> RST", session_id);
				invalid = true;
			}
			else {  // new session
				auto it = mappings_in.find(destination_port);
				if (it == mappings_in.end()) {
					DOLOG(logger::ll_debug, "No mapping for port %d", destination_port);
					invalid = true;
				}
				else if (flags & (FLAG_FIN | FLAG_RST | FLAG_PSH | FLAG_URG | FLAG_ACK)) {
					DOLOG(logger::ll_debug, "Invalid flags set (%s) combined with SYN in a new session -> RST", flags_to_str(flags).c_str());
					invalid = true;
					invalid_w_rst = !(flags & FLAG_RST);  // no RST if the flags already contain RST
				}
				else {
					uint32_t syn_cookie = my_syn_cookie(session_id, syn_cookie_salt);
					DOLOG(logger::ll_debug, "Session %" PRIx64 " using SYN cookie %08x, acking to %08x",
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

					std::unique_lock<std::mutex> lck(sessions_lock);
					sessions->erase(session_id);
					delete session;
				}
				else {
					// TODO
				}
			}
			else {  // start of new session
				uint32_t syn_cookie = my_syn_cookie(session_id, syn_cookie_salt) + 1;
				if (syn_cookie != my_seq_nr) {
					DOLOG(logger::ll_debug, "Invalid SYN-cookie %08x - expecting %08x", my_seq_nr, syn_cookie);
					send_tcp_packet(shm, out_name,
							a_to, a_from,  // swapped: reply
							destination_port, source_port,  // swapped: reply
							syn_cookie, peer_seq_nr + 1,
							FLAG_RST, window_size, { nullptr, 0 });
				}
				else {
					// allocate session
					session_t *new_session = new session_t;
					new_session->rx        = established;
					new_session->local_seq = syn_cookie;
					new_session->tx        = established;
					new_session->peer_seq  = peer_seq_nr;
					std::unique_lock<std::mutex> lck(sessions_lock);
					sessions->insert({ session_id, new_session });
				}
			}
		}
		else {
			DOLOG(logger::ll_debug, "Session %" PRIx64 " has an unexpected state", session_id);
		}

		// TODO

		if (invalid) {
			if (invalid_w_rst) {
				send_tcp_packet(shm, out_name,
						a_to, a_from,  // swapped: reply
						destination_port, source_port,  // swapped: reply
						0, peer_seq_nr + invalid_inc_ack,
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

void run_out(shm_message_queue *const shm, const std::string & out_name, shm_message_queue *const shm_out)
{
	while(!stop_flag) {
		shm_message_queue::message *m = shm->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_new, { });
		if (!m)
			continue;

		// TODO

		free(m);
	}
}

void run(shm_message_queue *const shm, const std::string & out_name,
	 const std::map<uint16_t, std::string> & mappings_in,
	 shm_message_queue *const shm_upper,
	 const std::string & icmp_error_name,
	 std::map<uint64_t, session_t *> *const sessions, std::mutex & sessions_lock,
	 const uint8_t syn_cookie_salt[16])
{
	std::thread rx([&] { run_in (shm, mappings_in, icmp_error_name, out_name, sessions, sessions_lock, syn_cookie_salt); });
	std::thread tx([&] { run_out(shm_upper, out_name, shm); });
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

	shm_message_queue shm_upper(name_upper, msg_queue_size);
	if (shm_upper.begin() == false) {
		fprintf(stderr, "Cannot initialize shared memory segment \"%s\"\n", name_upper.c_str());
		return 1;
	}
	
	std::map<uint64_t, session_t *> sessions;
	std::mutex sessions_lock;

	uint8_t syn_cookie_salt[16];  // key size required by SipHAsh
	if (getrandom(syn_cookie_salt, sizeof syn_cookie_salt, 0) == -1) {
		fprintf(stderr, "getrandom failed: %s\n", strerror(errno));
		return 1;
	}

	run(&shm, out_name, mappings_in, &shm_upper, icmp_error_name, &sessions, sessions_lock, syn_cookie_salt);

	return 0;
}
