#include <atomic>
#include <cassert>
#include <cerrno>
#include <cinttypes>
#include <climits>
#include <csignal>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <functional>
#include <map>
#include <mutex>
#include <thread>
#include <arpa/inet.h>
#include <iniparser/iniparser.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "common.h"
#include "utils/addresses.h"
#include "utils/gen.h"
#include "utils/log.h"
#include "utils/net.h"
#include "utils/queue.h"
#include "utils/shm.h"
#include "utils/shm_message.h"
#include "utils/stoi.h"
#include "utils/tcp-helpers.h"


struct gopher_session_t: public tcp_l7_session_t
{
	gopher_session_t(const uint64_t session_id, const std::string & out_name,
		shm_message_queue *const shm,
		const addr_ip4 from, const uint16_t from_port,
		const addr_ip4 to,   const uint16_t to_port):
		tcp_l7_session_t(session_id, out_name, shm, from, from_port, to, to_port)
	{
	}
};

std::atomic_bool stop_flag { false };

void sig_handler(int sig)
{
	stop_flag = true;
}

void access_log(const gopher_session_t *const hs, const std::string & url)
{
	DOLOG(logger::ll_info, "GOPHER req. by [%s]:%d: %s",
			hs->from.to_str('.', false).c_str(), hs->from_port,
			url.c_str());
}

void send_menu(gopher_session_t *const session,
		const std::string & base_path, const std::string & rel_path, const bool allow_parent_dir,
		const std::string & hostname)
{
	std::string doc;

	DIR *dir = opendir((base_path + rel_path).c_str());
	if (dir) {
		for(;;) {
			auto entry = readdir(dir);
			if (!entry)
				break;

			std::string name = entry->d_name;
			if ((name == "." || name == "..") && allow_parent_dir == false)
				continue;

			std::string ext;
			if (name.size() >= 4) {
				auto dot = name.rfind('.');
				if (dot != std::string::npos)
					ext = name.substr(dot);
			}

			std::string reply;
			if (entry->d_type == DT_DIR) {
				reply = "1" + rel_path + "/" + name;
			}
			else if (entry->d_type == DT_REG || entry->d_type == DT_LNK) {
				char type = '9';
				if (ext == ".txt" || ext == ".html" || ext == ".htm")
					type = '0';
				else if (ext == ".png" || ext == ".jpg" || ext == ".jpeg")
					type = 'I';
				else if (ext == ".gif")
					type = 'g';

				reply = type + name + "\t" + rel_path + "/" + name + "\t" + hostname + "\t70\r\n";
			}

			if (reply.empty() == false)
				doc += reply;
		}
	}

	if (doc.empty())
		doc = "3666\r\n";  // TODO sane error

	send_func(session, reinterpret_cast<const uint8_t *>(doc.c_str()), doc.size());
}

void process_gopher_request(gopher_session_t *const session, const std::string & base_path, const std::string & hostname)
{
	DOLOG(logger::ll_debug, "Gopher request handler running for session %" PRIx64, session->session_id);

	std::string recv_buffer;
	do {
		auto incoming = session->incoming.pop();
		recv_buffer += std::string(reinterpret_cast<const char *>(incoming.data()), incoming.size());
	}
	while(recv_buffer.find("\r\n") == std::string::npos);
	auto size = recv_buffer.size();
	recv_buffer = recv_buffer.substr(0, size - 2);

	if (recv_buffer.empty()) {  // root menu
		access_log(session, "ROOT MENU");
		send_menu(session, base_path, "", false, hostname);
	}
	else {
		std::string combined = base_path + "/" + recv_buffer;
		char *temp = realpath(combined.c_str(), nullptr);
		std::string path = temp?:"";
		if (!temp)
			DOLOG(logger::ll_info, "realpath(%s) returned an error: %s\n", combined.c_str(), strerror(errno));
		free(temp);

		struct stat st { };
		if (path.substr(0, base_path.size()) != base_path) {
			DOLOG(logger::ll_warning, "\"%s\" is an invalid path", path.c_str());
		}
		else if (stat(path.c_str(), &st) == -1) {
			DOLOG(logger::ll_warning, "Stat on \"%s\" failed: %s", path.c_str(), strerror(errno));
		}
		else {
			auto sub_path = path.substr(base_path.size());
			access_log(session, sub_path);

			if (st.st_mode & S_IFDIR)
				send_menu(session, base_path, sub_path, true, hostname);
			else if (st.st_mode & S_IFREG) {
				int fd = open(path.c_str(), O_RDONLY);
				if (fd != -1) {
					auto length = st.st_size;
					uint8_t buffer[4096];
					while(length > 0) {
						auto chunk_size = std::min(length, long(sizeof buffer));
						DOLOG(logger::ll_debug, "Sending %lu bytes, %lu left", chunk_size, length);

						if (int rc = read(fd, buffer, chunk_size); rc != chunk_size) {
							DOLOG(logger::ll_debug, "Short read on \"%s\"", path.c_str());
							break;
						}
						if (send_func(session, buffer, chunk_size) != chunk_size) {
							DOLOG(logger::ll_debug, "Short write on \"%s\"", path.c_str());
							break;
						}

						length -= chunk_size;
					}
					close(fd);
				}
				else {
					DOLOG(logger::ll_warning, "Cannot open \"%s\"", path.c_str());
				}
			}
			else {
				DOLOG(logger::ll_warning, "\"%s\" is not a directory or file", path.c_str());
			}
		}
	}

	fin_func(session);  // send FIN

	session->finished = true;
}

void run_in(shm_message_queue *const shm, const std::string & out_name,
		std::map<uint64_t, std::pair<std::thread *, gopher_session_t *> > *const sessions, std::mutex & sessions_lock,
		shm_message_queue *const shm_meta,
		const std::string & base_path, const std::string & hostname)
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

		gopher_session_t *hs = nullptr;
		{
			std::unique_lock<std::mutex> lck(sessions_lock);
			auto it = sessions->find(session_id);
			if (it == sessions->end()) {
				if (flags & MI_TCP_OPEN) {
					DOLOG(logger::ll_debug, "Session %" PRIx64 " not known - new session", session_id);
					hs = new gopher_session_t(
							session_id, out_name, shm,
							addr_ip4(from, from_len), from_port,
							addr_ip4(to, to_len), to_port);
					std::thread *th = new std::thread([hs, base_path, hostname] { process_gopher_request(hs, base_path, hostname); });
					auto rc = sessions->insert({ session_id, { th, hs } });
					assert(rc.second);
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
			DOLOG(logger::ll_warning, "Gopher session %" PRIx64 " not found", session_id);

		free(m);
	}
}

void run_meta(shm_message_queue *const shm_meta, std::map<uint64_t, std::pair<std::thread *, gopher_session_t *> > *const sessions, std::mutex & sessions_lock)
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

	DOLOG(logger::ll_warning, "Gopher meta handler stopping");
}

void run(shm_message_queue *const shm, const std::string & out_name,
		shm_message_queue *const shm_meta,
		std::map<uint64_t, std::pair<std::thread *, gopher_session_t *> > *const sessions, std::mutex & sessions_lock,
		const std::string & base_path, const std::string & hostname)
{
	std::thread rx  ([&] { run_in  (shm, out_name, sessions, sessions_lock, shm_meta, base_path, hostname); });
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

	DOLOG(logger::ll_info, "Gopher server starting...");

	dictionary *d = iniparser_load(cfg_file.c_str());
	for(int i=0; i<iniparser_getnsec(d); i++) {
		std::string section_name = iniparser_getsecname(d, i);
		if (section_name != "global" && section_name != "specific") {
			fprintf(stderr, "Section \"%s\" in configuration file is unknown\n", section_name.c_str());
			return 1;
		}
	}
	std::string name = iniparser_getstring(d, "global:lower-in-name", "");
	if (name.empty()) {
		fprintf(stderr, "\"lower-in-name\" under \"global\" missing\n");
		return 1;
	}
	std::string out_name = iniparser_getstring(d, "global:out-name", "");
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
	std::string base_path = iniparser_getstring(d, "specific:base-path", "");
	if (base_path.empty()) {
		fprintf(stderr, "\"base-path\" under \"specific\" missing\n");
		return 1;
	}
	std::string hostname = iniparser_getstring(d, "specific:hostname", "");
	if (hostname.empty()) {
		fprintf(stderr, "\"hostname\" under \"specific\" missing\n");
		return 1;
	}
	iniparser_freedict(d);

	char *temp = realpath(base_path.c_str(), nullptr);
	if (!temp) {
		fprintf(stderr, "realpath(%s) returned an error: %s\n", base_path.c_str(), strerror(errno));
		return 1;
	}
	base_path = temp;
	free(temp);
	DOLOG(logger::ll_info, "Using \"%s\" as base-path", base_path.c_str());

	signal(SIGINT, sig_handler);

	shm_message_queue *shm = create_shm(name, msg_queue_size);
	if (shm == nullptr)
		return 1;

	shm_message_queue *shm_meta = create_shm(name_meta, msg_queue_size_meta);
	if (shm_meta == nullptr)
		return 1;

	std::map<uint64_t, std::pair<std::thread *, gopher_session_t *> > sessions;
	std::mutex sessions_lock;

	run(shm, out_name, shm_meta, &sessions, sessions_lock, base_path, hostname);

	delete shm_meta;
	delete shm;

	return 0;
}
