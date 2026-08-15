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
	std::string test;
};

std::atomic_bool stop_flag { false };

void sig_handler(int sig)
{
	stop_flag = true;
}

void run_in(shm_message_queue *const shm, const std::string & out_name,
		std::map<uint64_t, http_session_t *> *const sessions, std::mutex & sessions_lock)
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

		std::unique_lock<std::mutex> lck(sessions_lock);
		auto it = sessions->find(session_id);

		// TODO

		free(m);
	}
}

void push_meta_reply(shm_message_queue *const shm_meta, const std::string & to, const std::string & reply, const uint64_t msg_nr)
{
	DOLOG(logger::ll_debug, "Pushing reply \"%s\" to \"%s\" (id: %" PRIu64 ")", reply.c_str(), to.c_str(), msg_nr);

	shm_message_queue::message *m_reply = allocate_shm_message(reply.size());
	m_reply->type   = shm_message_queue::msg_reply;
	m_reply->msg_nr = msg_nr;
	memcpy(m_reply->data, reply.c_str(), m_reply->size);
	shm_meta->send_message(to, m_reply, false);
	free(m_reply);
}

void run_meta(shm_message_queue *const shm_meta, std::map<uint64_t, http_session_t *> *const sessions, std::mutex & sessions_lock)
{
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
				session_id = my_stoi_hex(parts[1]);
			}
			else {
				DOLOG(logger::ll_error, "Invalid command (%s)", kv.c_str());
				free(m);
				continue;
			}
		}

		if (invalid) {
		}
		else if (action == open) {
			std::unique_lock<std::mutex> lck(sessions_lock);
			sessions->insert({ session_id.value(), new http_session_t() });
			// TODO check for duplicates?
		}
		else if (action == close) {
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

		free(m);
	}
}

void run(shm_message_queue *const shm, const std::string & out_name,
		shm_message_queue *const shm_meta,
		std::map<uint64_t, http_session_t *> *const sessions, std::mutex & sessions_lock)
{
	std::thread rx  ([&] { run_in  (shm, out_name, sessions, sessions_lock); });
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
