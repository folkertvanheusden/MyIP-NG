#include <atomic>
#include <cassert>
#include <cerrno>
#include <cinttypes>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <thread>
#include <arpa/inet.h>
#include <iniparser/iniparser.h>
#include <sys/stat.h>

#include "common.h"
#include "utils/addresses.h"
#include "utils/gen.h"
#include "utils/log.h"
#include "utils/net.h"
#include "utils/shm.h"
#include "utils/shm_message.h"
#include "utils/stoi.h"


const std::string http_base_path = "./www";

struct http_session_t
{
	std::string recv_buffer;

	http_session_t() {
	}
};

std::atomic_bool stop_flag { false };

void sig_handler(int sig)
{
	stop_flag = true;
}

void abort_session(const uint64_t session_id, http_session_t *const hs, shm_message_queue *const shm, const std::string & out_name)
{
	shm_message_queue::message *abort_msg = allocate_shm_message(12);
	memcpy(&abort_msg->data[0], &session_id, 8);
	uint32_t flags = 1;
	memcpy(&abort_msg->data[8], &flags, 4);

	if (shm->send_message(out_name, abort_msg, true) == false)
		DOLOG(logger::ll_warning, "Cannot send to %s", out_name.c_str());

	free(abort_msg);
}

bool send_http_header(const uint64_t session_id, shm_message_queue *const shm, const std::string & out_name, const int which, const size_t payload_size, const bool fin, const std::string & message, const std::string & mime_type)
{
	DOLOG(logger::ll_debug, "Sending HTTP %d code (\"%s\")", which, message.c_str());

	const std::string http_headers = std::format("HTTP/1.0 {} {}\r\nServer: MyIP-NG HTTPd\r\nContent-Type: {}\r\nContent-Size: {}\r\n\r\n", which, message, mime_type, payload_size);

	shm_message_queue::message *http_reply = allocate_shm_message(12 + http_headers.size());
	memcpy(&http_reply->data[0], &session_id, 8);
	uint32_t flags = fin ? 1 : 0;
	memcpy(&http_reply->data[8], &flags, 4);
	memcpy(&http_reply->data[12], http_headers.c_str(), http_reply->size - 12);

	bool rc = shm->send_message(out_name, http_reply, true);
	if (rc == false)
		DOLOG(logger::ll_warning, "Cannot send HTTP headers to %s", out_name.c_str());

	free(http_reply);

	return rc;
}

void process_http_request(const uint64_t session_id, http_session_t *const hs, shm_message_queue *const shm, const std::string & out_name)
{
	bool        first_line = true;
	std::string url;
	auto        lines = split(hs->recv_buffer, "\r\n");
	for(auto & line: lines) {
		if (first_line) {
			first_line = false;

			auto parts = split(line, " ");
			if (parts.size() != 3) {
				send_http_header(session_id, shm, out_name, 405, 0, true, "Can't make cheese from your supposedly HTTP request", "text/html");
				return;
			}

			if (parts[0] == "GET") {
				url = line.substr(4);
				auto space = url.find(" ");
				if (space == std::string::npos) {  // invalid
					abort_session(session_id, hs, shm, out_name);
					return;
				}
				url = url.substr(0, space);
			}
			else {
				send_http_header(session_id, shm, out_name, 501, 0, true, "Only GET please", "text/html");
				return;
			}
		}
	}

	if (url.empty()) {
		send_http_header(session_id, shm, out_name, 405, 0, true, "URL missing", "text/html");
		return;
	}

	DOLOG(logger::ll_debug, "Processing URL \"%s\"", url.c_str());

	// TODO: compare with canonical path (std::filesystem::canonical) instead
	if (url.find("..") != std::string::npos || url.find("~") != std::string::npos) {
		send_http_header(session_id, shm, out_name, 500, 0, true, "Invalid URL", "text/html");
		return;
	}

	if (url == "/")
		url = "/index.html";
	else if (url[0] != '/')
		url = "/" + url;

	DOLOG(logger::ll_info, "HTTP GET: %s", url.c_str());

	std::string local_file = http_base_path + url;
	int fd = open(local_file.c_str(), O_RDONLY);
	if (fd == -1) {
		DOLOG(logger::ll_debug, "Cannot open local file \"%s\": %s", local_file.c_str(), strerror(errno));
		send_http_header(session_id, shm, out_name, 404, 0, true, "Not found", "text/html");
		return;
	}

	struct stat st { };
	if (fstat(fd, &st) == -1) {
		close(fd);
		DOLOG(logger::ll_debug, "Stat on \"%s\" failed: %s", local_file.c_str(), strerror(errno));
		send_http_header(session_id, shm, out_name, 500, 0, true, "Unknown error", "text/html");
		return;
	}

	std::string mime_type { "text/html" };
	auto dot = url.rfind(".");
	if (dot != std::string::npos) {
		auto ext = url.substr(dot + 1);
		if (ext == "css")
			mime_type = "text/css";
		else if (ext == "ico")
			mime_type = "image/vnd.microsoft.icon";
		else if (ext == "png")
			mime_type = "image/png";
		else if (ext == "svg")
			mime_type = "image/svg+xml";
		else
			DOLOG(logger::ll_debug, "\"%s\" is an unkown file type", ext.c_str());
	}

	auto length { st.st_size };
	if (send_http_header(session_id, shm, out_name, 200, length, false, "Ok!", mime_type)) {
		while(length > 0) {
			auto chunk_size = std::min(length, 4096l);
			DOLOG(logger::ll_debug, "Sending %lu bytes, %lu left", chunk_size, length);

			shm_message_queue::message *http_reply = allocate_shm_message(12 + chunk_size);
			if (int rc = read(fd, &http_reply->data[12], chunk_size); rc != chunk_size) {
				DOLOG(logger::ll_debug, "Short read on \"%s\"", local_file.c_str());
				break;
			}
			memcpy(&http_reply->data[0], &session_id, 8);
			uint32_t flags = length - chunk_size == 0 ? 1 : 0;
			memcpy(&http_reply->data[8], &flags, 4);

			if (shm->send_message(out_name, http_reply, true) == false)
				DOLOG(logger::ll_warning, "Cannot send to %s", out_name.c_str());

			free(http_reply);

			length -= chunk_size;
		}
	}

	close(fd);
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
		std::map<uint64_t, http_session_t *> *const sessions, std::mutex & sessions_lock,
		shm_message_queue *const shm_meta)
{
	set_thread_name("run_in");

	std::vector<uint64_t> finish_sessions;

	while(!stop_flag) {
		// finish_sessions
		{
			std::unique_lock<std::mutex> lck(sessions_lock);
			for(auto & session_id: finish_sessions) {
				auto it = sessions->find(session_id);
				if (it == sessions->end())
					DOLOG(logger::ll_error, "Internal error: session %" PRIx64 " not known", session_id);
				else {
					delete it->second;
					sessions->erase(it);
				}
			}
			finish_sessions.clear();
		}

		// process incoming data
		shm_message_queue::message *m = shm->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_new, { });
		if (!m)
			continue;

		if (m->size < 12) {
			DOLOG(logger::ll_error, "SHM message from %s too small (%zu bytes)", m->sender, m->size);
			free(m);
			continue;
		}

		uint64_t session_id = 0;
		memcpy(&session_id, m->data, sizeof(session_id));
		uint32_t flags = 0;
		memcpy(&flags, &m->data[8], sizeof(flags));

		DOLOG(logger::ll_debug, "Data for session %" PRIx64 "%s", session_id, flags & 1 ? " +FIN": "");

		http_session_t *hs = nullptr;
		{
			std::unique_lock<std::mutex> lck(sessions_lock);
			auto it = sessions->find(session_id);
			if (it == sessions->end()) {
				DOLOG(logger::ll_debug, "Session %" PRIx64 " not known - new session", session_id);
				it = sessions->insert({ session_id, new http_session_t() }).first;
			}

			hs = it->second;
		}

		if (hs) {
			if (m->size > 12) {
				std::string temp(reinterpret_cast<const char *>(m->data + 12), m->size - 12);
				hs->recv_buffer += temp;

				size_t end_marker = hs->recv_buffer.find("\r\n\r\n");
				if (end_marker != std::string::npos || (flags & 1 /* FIN */)) {
					std::thread handler([&] {
							set_thread_name("http_handler");
							process_http_request(session_id, hs, shm, out_name);

							std::unique_lock<std::mutex> lck(sessions_lock);
							finish_sessions.push_back(session_id);
						});
					handler.detach();
				}
				// what if this triggers when the processing thread is already/still running?
				else if (hs->recv_buffer.size() > 4096) {
					abort_session(session_id, hs, shm, out_name);

					std::unique_lock<std::mutex> lck(sessions_lock);
					finish_sessions.push_back(session_id);
				}
			}
		}
		else {
			DOLOG(logger::ll_warning, "HTTP session %" PRIx64 " not found", session_id);
		}

		free(m);
	}
}

void run_meta(shm_message_queue *const shm_meta, std::map<uint64_t, http_session_t *> *const sessions, std::mutex & sessions_lock)
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

		enum { open, close }    action  = close;
		std::optional<uint64_t> session_id;
		bool                    invalid = false;

		for(auto & line: lines) {
			auto parts = split(line, "=");
			DOLOG(logger::ll_debug, "Processing \"%s\"", line.c_str());

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
		else if (action == open) {
			DOLOG(logger::ll_debug, "\"open\" for %" PRIx64 " received", session_id.value());

			{
				std::unique_lock<std::mutex> lck(sessions_lock);
				auto it = sessions->find(session_id.value());
				if (it == sessions->end())
					sessions->insert({ session_id.value(), new http_session_t() });
			}

		}
		else if (action == close) {
			DOLOG(logger::ll_debug, "\"close\" for %" PRIx64 " received", session_id.value());

			std::unique_lock<std::mutex> lck(sessions_lock);
			auto it = sessions->find(session_id.value());
			if (it != sessions->end()) {
				delete it->second;
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
		std::map<uint64_t, http_session_t *> *const sessions, std::mutex & sessions_lock)
{
	std::thread rx  ([&] { run_in  (shm, out_name, sessions, sessions_lock, shm_meta); });
	std::thread meta([&] { run_meta(shm_meta, sessions, sessions_lock     ); });
	meta.join();
	rx.join();
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
	iniparser_freedict(d);

	signal(SIGINT, sig_handler);

	shm_message_queue *shm = create_shm(name, msg_queue_size);
	if (shm == nullptr)
		return 1;

	shm_message_queue *shm_meta = create_shm(name_meta, msg_queue_size_meta);
	if (shm_meta == nullptr)
		return 1;

	std::map<uint64_t, http_session_t *> sessions;
	std::mutex sessions_lock;

	run(shm, out_name, shm_meta, &sessions, sessions_lock);

	delete shm;

	return 0;
}
