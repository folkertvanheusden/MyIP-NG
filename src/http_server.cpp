#include <atomic>
#include <cassert>
#include <cerrno>
#include <cinttypes>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <map>
#include <mutex>
#include <thread>
#include <arpa/inet.h>
#include <iniparser/iniparser.h>
#include <sys/stat.h>

#include "common.h"
#include "tcp.h"
#include "utils/addresses.h"
#include "utils/gen.h"
#include "utils/log.h"
#include "utils/net.h"
#include "utils/queue.h"
#include "utils/shm.h"
#include "utils/shm_message.h"
#include "utils/stoi.h"


const std::string http_base_path = "./www";

struct http_session_t
{
	const uint64_t    session_id;
	const std::string out_name;
	shm_message_queue *const shm;
	const addr_ip4    from;
	const uint16_t    from_port;
	const addr_ip4    to;
	const uint16_t    to_port;
	const bool        is_tls;

	std::atomic_bool  finished  { false };
	std::atomic_bool  stop_flag { false };
	queue<std::vector<uint8_t> > incoming;

	http_session_t(const uint64_t session_id, const std::string & out_name,
		shm_message_queue *const shm,
		const addr_ip4 from, const uint16_t from_port,
		const addr_ip4 to,   const uint16_t to_port,
		const bool is_tls):
		session_id(session_id), out_name(out_name), shm(shm),
		from(from), from_port(from_port),
		to  (to  ), to_port  (to_port  ),
		is_tls(is_tls)
	{
	}
};

struct http_session_tls_t: public http_session_t
{
	// TODO bearssl stuff
};

std::atomic_bool stop_flag { false };

void sig_handler(int sig)
{
	stop_flag = true;
}

int send_func(void *const context, const uint8_t *const from, const size_t n)
{
	int rc = -1;
	http_session_t *session { reinterpret_cast<http_session_t *>(context) };

	if (from == nullptr && n == 0) {
		shm_message_queue::message *end_msg = allocate_shm_message(12);
		memcpy(&end_msg->data[0], &session->session_id, 8);
		uint32_t flags = MI_TCP_FIN;
		memcpy(&end_msg->data[8], &flags, 4);

		if (session->shm->send_message(session->out_name, end_msg, true) == false)
			DOLOG(logger::ll_warning, "Cannot send FIN message to %s", session->out_name.c_str());
		else
			rc = 0;

		free(end_msg);
	}
	else {
		shm_message_queue::message *data_msg = allocate_shm_message(12 + n);
		memcpy(&data_msg->data[0], &session->session_id, 8);
		uint32_t flags = 0;
		memcpy(&data_msg->data[8], &flags, 4);
		memcpy(&data_msg->data[12], from, n);

		if (session->shm->send_message(session->out_name, data_msg, true) == false)
			DOLOG(logger::ll_warning, "Cannot send HTTP headers to %s", session->out_name.c_str());
		else
			rc = n;

		free(data_msg);
	}

	return rc;
}

int recv_func(void *const context, uint8_t *const to, const size_t n)
{
	if (n == 0)
		return 0;

	http_session_tls_t *session { reinterpret_cast<http_session_tls_t *>(context) };

	uint8_t *p    = to;
	size_t   todo = n;
	do {
		auto   values = session->incoming.pop();
		size_t v_n    = values.size();
		memcpy(p, values.data(), todo);

		if (v_n > todo) {
			session->incoming.unpop(std::vector<uint8_t>(values.data() + todo, values.data() + v_n));
			todo = 0;
		}
		else {
			todo -= v_n;
			p    += v_n;
		}
	} while(todo > 0);

	return n;
}

void abort_session(http_session_t *const session)
{
	send_func(session, nullptr, 0);
}

bool send_http_header(http_session_t *const session, const int which, const size_t payload_size, const bool fin, const std::string & message, const std::string & mime_type)
{
	DOLOG(logger::ll_debug, "Sending HTTP %d code (\"%s\"), announcing %zu bytes payload", which, message.c_str(), payload_size);

	const std::string http_headers = std::format("HTTP/1.0 {} {}\r\nServer: MyIP-NG HTTPd\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n", which, message, mime_type, payload_size);
	const size_t headers_size = http_headers.size();
	bool rc = send_func(session, reinterpret_cast<const uint8_t *>(http_headers.c_str()), headers_size) == headers_size;

	if (fin && rc) {
		DOLOG(logger::ll_debug, "Sending FIN");
		rc = send_func(session, nullptr, 0) == 0;
	}

	return rc;
}

void access_log(const http_session_t *const hs, const std::string & url, const int code)
{
	DOLOG(logger::ll_info, "HTTP GET(%d) by [%s]:%d: %s",
			code,
			hs->from.to_str('.', false).c_str(), hs->from_port,
			url.c_str());
}

void process_http_request(http_session_t *const session)
{
	DOLOG(logger::ll_debug, "HTTP request handler running for session %" PRIx64, session->session_id);

	std::string recv_buffer;
	do {
		auto incoming = session->incoming.pop();
		recv_buffer += std::string(reinterpret_cast<const char *>(incoming.data()), incoming.size());
	}
	while(recv_buffer.find("\r\n\r\n") == std::string::npos);

	bool        first_line = true;
	std::string url;
	auto        lines = split(recv_buffer, "\r\n");
	for(auto & line: lines) {
		if (first_line) {
			first_line = false;

			auto parts = split(line, " ");
			if (parts.size() != 3) {
				send_http_header(session,
						405, 0, true, "Can't make cheese from your supposedly HTTP request", "text/html");
				session->finished = true;
				return;
			}

			if (parts[0] == "GET") {
				url = line.substr(4);
				auto space = url.find(" ");
				if (space == std::string::npos) {  // invalid
					abort_session(session);
					session->finished = true;
					return;
				}
				url = url.substr(0, space);
			}
			else {
				send_http_header(session,
						501, 0, true, "Only GET please", "text/html");
				session->finished = true;
				return;
			}
		}
	}

	if (url.empty()) {
		send_http_header(session,
				405, 0, true, "URL missing", "text/html");
		session->finished = true;
		return;
	}

	DOLOG(logger::ll_debug, "Processing URL \"%s\"", url.c_str());

	// TODO: compare with canonical path (std::filesystem::canonical) instead
	if (url.find("..") != std::string::npos || url.find("~") != std::string::npos) {
		send_http_header(session,
				500, 0, true, "Invalid URL", "text/html");
		session->finished = true;
		return;
	}

	if (url == "/")
		url = "/index.html";
	else if (url[0] != '/')
		url = "/" + url;

	std::string local_file = http_base_path + url;
	int fd = open(local_file.c_str(), O_RDONLY);
	if (fd == -1) {
		DOLOG(logger::ll_debug, "Cannot open local file \"%s\": %s", local_file.c_str(), strerror(errno));
		send_http_header(session,
				404, 0, true, "Not found", "text/html");
		access_log(session, url, 404);
		session->finished = true;
		return;
	}

	struct stat st { };
	if (fstat(fd, &st) == -1) {
		close(fd);
		DOLOG(logger::ll_debug, "Stat on \"%s\" failed: %s", local_file.c_str(), strerror(errno));
		send_http_header(session,
				500, 0, true, "Unknown error", "text/html");
		access_log(session, url, 500);
		session->finished = true;
		return;
	}

	std::string mime_type { "text/plain" };
	auto dot = url.rfind(".");
	if (dot != std::string::npos) {
		auto ext = url.substr(dot + 1);
		if (ext == "css")
			mime_type = "text/css";
		else if (ext == "html" || ext == "htm")
			mime_type = "text/html";
		else if (ext == "ico")
			mime_type = "image/vnd.microsoft.icon";
		else if (ext == "png")
			mime_type = "image/png";
		else if (ext == "jpg")
			mime_type = "image/jpeg";
		else if (ext == "svg")
			mime_type = "image/svg+xml";
		else
			DOLOG(logger::ll_debug, "\"%s\" is an unkown file type", ext.c_str());
	}

	auto length { st.st_size };
	if (send_http_header(session, 200, length, false, "Ok!", mime_type)) {
		uint8_t buffer[4096];
		while(length > 0) {
			auto chunk_size = std::min(length, long(sizeof buffer));
			DOLOG(logger::ll_debug, "Sending %lu bytes, %lu left", chunk_size, length);

			if (int rc = read(fd, buffer, chunk_size); rc != chunk_size) {
				DOLOG(logger::ll_debug, "Short read on \"%s\"", local_file.c_str());
				break;
			}

			if (send_func(session, buffer, chunk_size) != chunk_size) {
				DOLOG(logger::ll_debug, "Short write on \"%s\"", local_file.c_str());
				break;
			}

			length -= chunk_size;
		}

		access_log(session, url, 200);
	}

	close(fd);

	send_func(session, nullptr, 0);  // send FIN

	session->finished = true;
}

void push_meta_reply(shm_message_queue *const shm_meta, const std::string & to, const std::string & reply)
{
	DOLOG(logger::ll_debug, "Pushing reply to \"%s\"", to.c_str());

	shm_message_queue::message *m_reply = allocate_shm_message(reply.size());
	m_reply->type   = shm_message_queue::msg_reply;
	memcpy(m_reply->data, reply.c_str(), m_reply->size);
	shm_meta->send_message(to, m_reply, true);
	free(m_reply);
}

void run_in(shm_message_queue *const shm, const std::string & out_name,
		std::map<uint64_t, std::pair<std::thread *, http_session_t *> > *const sessions, std::mutex & sessions_lock,
		shm_message_queue *const shm_meta,
		const bool is_tls)
{
	set_thread_name("run_in");

	while(!stop_flag) {
		// finish_sessions
		{
			std::vector<uint64_t> delete_these;

			std::unique_lock<std::mutex> lck(sessions_lock);
			for(auto & session: *sessions) {
				if (session.second.second->finished) {
					DOLOG(logger::ll_debug, "Deleting session/thread %" PRIx64, session.first);
					session.second.second->stop_flag = true;
					session.second.first->join();
					delete session.second.first;
					delete session.second.second;
					delete_these.push_back(session.first);
				}
			}

			for(auto session: delete_these)
				sessions->erase(session);
		}

		// process incoming data
		shm_message_queue::message *m = shm->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_any, { });
		if (!m)
			continue;

		uint64_t       session_id   = 0;
                size_t         from_len     = 0;
		uint16_t       from_port    = 0;
                size_t         to_len       = 0;
		uint16_t       to_port      = 0;
                size_t         pl_len       = 0;
		uint32_t       flags        = 0;
                const uint8_t *from         = nullptr;
                const uint8_t *to           = nullptr;
                const uint8_t *pl           = nullptr;
		if (unwrap_message_up_tcp(
				m,
				&session_id,
				&from_len, &from,
				&from_port,
				&to_len, &to,
				&to_port,
				&flags,
				&pl_len, &pl) == false) {
                        DOLOG(logger::ll_error, "ERR) Corrupt message in shared memory segment!");
                        free(m);
                        continue; 
		}

		DOLOG(logger::ll_debug, "Data for session %" PRIx64 "%s", session_id, flags & MI_TCP_FIN ? " +FIN": "");

		http_session_t *hs = nullptr;
		{
			std::unique_lock<std::mutex> lck(sessions_lock);
			auto it = sessions->find(session_id);
			if (it == sessions->end()) {
				if (flags & MI_TCP_OPEN) {
					DOLOG(logger::ll_debug, "Session %" PRIx64 " not known - new session", session_id);
					hs = new http_session_t(
							session_id, out_name, shm,
							addr_ip4(from, from_len), from_port,
							addr_ip4(to, to_len), to_port, is_tls);
					std::thread *th = new std::thread([hs] { process_http_request(hs); });
					auto rc = sessions->insert({ session_id, { th, hs } }).second;
					assert(rc);
				}
				// TODO MI_TCP_CLOSE
				else {
					DOLOG(logger::ll_debug, "Session %" PRIx64 " not known");
					free(m);
					continue;
				}
			}
			else {
				hs = it->second.second;
			}
		}

		if (hs)
			hs->incoming.push(std::vector<uint8_t>(pl, &pl[pl_len]));
		else
			DOLOG(logger::ll_warning, "HTTP session %" PRIx64 " not found", session_id);

		free(m);
	}
}

void run_meta(shm_message_queue *const shm_meta, std::map<uint64_t, std::pair<std::thread *, http_session_t *> > *const sessions, std::mutex & sessions_lock)
{
	set_thread_name("run_meta");

	while(!stop_flag) {
		shm_message_queue::message *m = shm_meta->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_any, { });
		if (!m)
			continue;

		std::string kv(reinterpret_cast<const char *>(m->data), m->size);
		auto lines = split(kv, "\n");
		if (lines.size() < 2) {
			DOLOG(logger::ll_error, "ERR) TCP meta message missing data");
			free(m);
			continue;
		}

		enum { close }          action  = close;
		std::optional<uint64_t> session_id;
		bool                    invalid = false;

		for(auto & line: lines) {
			auto parts = split(line, "=");
			DOLOG(logger::ll_debug, "Processing \"%s\"", line.c_str());

			if (parts[0] == "action") {
				if (parts[1] == "close")
					action = close;
				else {
					DOLOG(logger::ll_error, "ERR) TCP meta: invalid action \"%s\"", parts[1].c_str());
					invalid = true;
					break;
				}
			}
			else if (parts[0] == "session-id") {
				session_id = my_stoull_hex(parts[1]);
			}
			else {
				DOLOG(logger::ll_error, "Invalid command (%s)", kv.c_str());
				free(m);
				continue;
			}
		}

		if (invalid) {
			DOLOG(logger::ll_warning, "Ignoring invalid shm command");
		}
		else if (action == close) {
			DOLOG(logger::ll_debug, "\"close\" for %" PRIx64 " received", session_id.value());

			std::unique_lock<std::mutex> lck(sessions_lock);
			auto it = sessions->find(session_id.value());
			if (it != sessions->end()) {
				it->second.second->stop_flag = true;
				it->second.first->join();
				delete it->second.first;
				delete it->second.second;
				sessions->erase(it);
			}
			else {
				DOLOG(logger::ll_warning, "Session %" PRIx64 " already gone", session_id.value());
			}
		}
		else {
			DOLOG(logger::ll_warning, "Unexpected state");
		}

		free(m);
	}

	DOLOG(logger::ll_warning, "HTTP meta handler stopping");
}

void run(shm_message_queue *const shm, const std::string & out_name,
		shm_message_queue *const shm_meta,
		std::map<uint64_t, std::pair<std::thread *, http_session_t *> > *const sessions, std::mutex & sessions_lock,
		const bool is_tls)
{
	std::thread rx  ([&] { run_in  (shm, out_name, sessions, sessions_lock, shm_meta, is_tls); });
	std::thread meta([&] { run_meta(shm_meta,      sessions, sessions_lock); });
	meta.join();
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

	DOLOG(logger::ll_info, "HTTP server starting...");

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
	std::string name_meta = iniparser_getstring(d, "global:name-meta",  "");
	if (name_meta.empty()) {
		fprintf(stderr, "\"name-meta\" under \"global\" missing\n");
		return 1;
	}
	int msg_queue_size_meta = iniparser_getint(d, "specific:meta-queue-size", 512);
	int is_tls = iniparser_getboolean(d, "specific:enable-tls", false);
	iniparser_freedict(d);

	signal(SIGINT, sig_handler);

	shm_message_queue *shm = create_shm(name, msg_queue_size);
	if (shm == nullptr)
		return 1;

	shm_message_queue *shm_meta = create_shm(name_meta, msg_queue_size_meta);
	if (shm_meta == nullptr)
		return 1;

	std::map<uint64_t, std::pair<std::thread *, http_session_t *> > sessions;
	std::mutex sessions_lock;

	run(shm, out_name, shm_meta, &sessions, sessions_lock, is_tls);

	delete shm;

	return 0;
}
