#include <atomic>
#include <cassert>
#include <cerrno>
#include <cinttypes>
#include <csignal>
#include <cstring>
#include <map>
#include <mutex>
#include <thread>
#include <arpa/inet.h>
#include <iniparser/iniparser.h>

#include "common.h"
#include "utils/addresses.h"
#include "utils/gen.h"
#include "utils/log.h"
#include "utils/net.h"
#include "utils/shm.h"
#include "utils/shm_message.h"
#include "utils/stoi.h"


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

void push_meta_reply(shm_message_queue *const shm_meta, const std::string & to, const std::string & reply)
{
	DOLOG(logger::ll_debug, "Pushing reply to \"%s\"", to.c_str());

	shm_message_queue::message *m_reply = allocate_shm_message(reply.size());
	m_reply->type   = shm_message_queue::msg_reply;
	memcpy(m_reply->data, reply.c_str(), m_reply->size);
	shm_meta->send_message(to, m_reply, false);
	free(m_reply);
}

void run_in(shm_message_queue *const shm, const std::string & out_name,
		std::map<uint64_t, http_session_t *> *const sessions, std::mutex & sessions_lock,
		shm_message_queue *const shm_meta)
{
	while(!stop_flag) {
		shm_message_queue::message *m = shm->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_new, { });
		if (!m)
			continue;

		if (m->size < 8) {
			DOLOG(logger::ll_error, "SHM message from %s too small (%zu bytes)", m->sender, m->size);
			free(m);
			continue;
		}

		uint64_t session_id = 0;
		memcpy(&session_id, m->data, sizeof(uint64_t));

		DOLOG(logger::ll_debug, "Data for session %" PRIx64, session_id);

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
			if (m->size > 8) {
				std::string temp(reinterpret_cast<const char *>(m->data + 8), m->size - 8);
				hs->recv_buffer += temp;

				size_t end_marker = hs->recv_buffer.find("\r\n\r\n");
				if (end_marker == std::string::npos)
					end_marker = hs->recv_buffer.find("\n\n");
				if (end_marker != std::string::npos) {
					DOLOG(logger::ll_debug, "Replying to HTTP request for %" PRIx64 " via %s", session_id, out_name.c_str());
					const std::string http_payload = "Hello, world!";
					const std::string http_headers = std::format("HTTP/1.0 200 All good sofar\r\nContent-Type: text/html\r\nContent-Size: {}\r\n\r\n", http_payload.size());
					const std::string http_data = http_headers + http_payload;

					shm_message_queue::message *http_reply = allocate_shm_message(12 + http_data.size());
					memcpy(&http_reply->data[0], &session_id, 8);
					uint32_t flags = 1;  // send FIN in-line
					memcpy(&http_reply->data[8], &flags, 4);
					memcpy(&http_reply->data[12], http_data.c_str(), http_reply->size - 12);

					if (shm->send_message(out_name, http_reply, false) == false)
						DOLOG(logger::ll_warning, "Cannot send to %s", out_name.c_str());

					free(http_reply);
				}
			}
		}
		else {
			DOLOG(logger::ll_warning, "HTTP session %" PRIx64 " not found", session_id);
		}

		// TODO

		free(m);
	}
}

void run_meta(shm_message_queue *const shm_meta, std::map<uint64_t, http_session_t *> *const sessions, std::mutex & sessions_lock)
{
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

			push_meta_reply(shm_meta, m->sender, "action=pull");
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
