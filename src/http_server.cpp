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
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

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


const std::string http_base_path = "./www";

struct http_session_t: public tcp_l7_session_t
{
	WOLFSSL_CTX      *const ctx;
	WOLFSSL          *ssl { nullptr };

	http_session_t(const uint64_t session_id,
		shm_message_queue *const shm_in, shm_message_queue *const shm_out,
		const addr_ip4 from, const uint16_t from_port,
		const addr_ip4 to,   const uint16_t to_port,
		WOLFSSL_CTX *const ctx):
		tcp_l7_session_t(session_id, shm_in, shm_out, from, from_port, to, to_port),
		ctx(ctx)
	{
		assert(shm_in);
		assert(shm_out);
	}
};

std::atomic_bool stop_flag { false };

std::atomic_bool please_terminate { false };

void sig_handler(int sig)
{
	if (sig == SIGINT)
		stop_flag = true;
	if (sig == SIGTERM)
		please_terminate = true;
}

bool send_http_header(http_session_t *const session, const int which, const size_t payload_size, const std::string & message, const std::string & mime_type)
{
	DOLOG(logger::ll_debug, "Sending HTTP %d code (\"%s\"), announcing %zu bytes payload", which, message.c_str(), payload_size);

	const std::string http_headers = std::format("HTTP/1.0 {} {}\r\nServer: MyIP-NG HTTPd\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n", which, message, mime_type, payload_size);
	const size_t headers_size { http_headers.size() };

	size_t done = 0;
	if (session->ctx)
		done = wolfSSL_write(session->ssl, http_headers.c_str(), headers_size);
	else
		done = send_func(session, reinterpret_cast<const uint8_t *>(http_headers.c_str()), headers_size);
	if (done != headers_size) {
		DOLOG(logger::ll_debug, "Send failed, exp to send: %zu, actual send: %zd", headers_size, done);
		return false;
	}
	return true;
}

void access_log(const http_session_t *const hs, const std::string & url, const int code)
{
	DOLOG(logger::ll_info, "HTTP%s GET(%d) by [%s]:%d: %s",
			hs->ssl ? "S":"",
			code,
			hs->from.to_str('.', false).c_str(), hs->from_port,
			url.c_str());
}

int my_wolfssl_receive(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
	http_session_t *session { reinterpret_cast<http_session_t *>(ctx) };

	if (recv_func(session, reinterpret_cast<uint8_t *>(buf), sz) == -1) {
		DOLOG(logger::ll_debug, "Receive failure, session %" PRIx64, session->session_id);
		return 0;  // connection closed
	}

	return sz;
}

int my_wolfssl_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
	http_session_t *session { reinterpret_cast<http_session_t *>(ctx) };

	if (send_func(session, reinterpret_cast<const uint8_t *>(buf), sz) == -1) {
		DOLOG(logger::ll_debug, "Send failure, session %" PRIx64, session->session_id);
		return 0;  // connection closed
	}

	return sz;
}

void end_session(http_session_t *const session)
{
	if (session->ssl)
		wolfSSL_free(session->ssl);
	fin_func(session);
	session->finished = true;
}

void process_http_request(http_session_t *const session)
{
	DOLOG(logger::ll_debug, "HTTP request handler running for session %" PRIx64, session->session_id);

	if (session->ctx) {
		session->ssl = wolfSSL_new(session->ctx);
		wolfSSL_SetIOReadCtx (session->ssl, session);
		wolfSSL_SetIOWriteCtx(session->ssl, session);
	}

	std::string recv_buffer;
	do {
		if (recv_buffer.size() > 32768) {
			DOLOG(logger::ll_debug, "DDOS error?");
			end_session(session);
			return;
		}

		if (session->ssl) {
			char c = 0;
			if (wolfSSL_read(session->ssl, &c, 1) != 1) {
				DOLOG(logger::ll_debug, "Read error");
				end_session(session);
				return;
			}
			recv_buffer += c;
		}
		else {
			printf("hier001\n");
			auto incoming = session->incoming.pop();
			recv_buffer += std::string(reinterpret_cast<const char *>(incoming.data()), incoming.size());
		}
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
						405, 0, "Can't make cheese from your supposedly HTTP request", "text/html");
				end_session(session);
				return;
			}

			if (parts[0] == "GET") {
				url = line.substr(4);
				auto space = url.find(" ");
				if (space == std::string::npos) {  // invalid
					end_session(session);
					return;
				}
				url = url.substr(0, space);
			}
			else {
				send_http_header(session,
						501, 0, "Only GET please", "text/html");
				end_session(session);
				return;
			}
		}
	}

	if (url.empty()) {
		send_http_header(session,
				405, 0, "URL missing", "text/html");
		end_session(session);
		return;
	}

	DOLOG(logger::ll_debug, "Processing URL \"%s\"", url.c_str());

	// TODO: compare with canonical path (std::filesystem::canonical) instead
	if (url.find("..") != std::string::npos || url.find("~") != std::string::npos) {
		send_http_header(session,
				500, 0, "Invalid URL", "text/html");
		end_session(session);
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
				404, 0, "Not found", "text/html");
		access_log(session, url, 404);
		end_session(session);
		return;
	}

	struct stat st { };
	if (fstat(fd, &st) == -1) {
		close(fd);
		DOLOG(logger::ll_debug, "Stat on \"%s\" failed: %s", local_file.c_str(), strerror(errno));
		send_http_header(session,
				500, 0, "Unknown error", "text/html");
		access_log(session, url, 500);
		end_session(session);
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
	if (send_http_header(session, 200, length, "OK!", mime_type)) {
		uint8_t buffer[4096];
		while(length > 0 && session->stop_flag == false && stop_flag == false) {
			auto chunk_size = std::min(length, long(sizeof buffer));
			DOLOG(logger::ll_debug, "Sending %lu bytes, %lu left", chunk_size, length);

			if (int rc = read(fd, buffer, chunk_size); rc != chunk_size) {
				DOLOG(logger::ll_debug, "Short read on \"%s\"", local_file.c_str());
				break;
			}

			if (session->ssl) {
				if (wolfSSL_write(session->ssl, buffer, chunk_size) != chunk_size) {
					DOLOG(logger::ll_debug, "Short write on \"%s\"", local_file.c_str());
					break;
				}
			}
			else {
				if (send_func(session, buffer, chunk_size) != chunk_size) {
					DOLOG(logger::ll_debug, "Short write on \"%s\"", local_file.c_str());
					break;
				}
			}

			length -= chunk_size;
		}

		access_log(session, url, 200);
	}

	close(fd);

	end_session(session);
}

void delete_session(std::pair<std::thread *, http_session_t *> & s)
{
	s.second->stop_flag = true;
	if (s.first) {
		s.first->join();
		delete s.first;
	}
	delete s.second->shm_to_l7;
	delete s.second->shm_from_l7;
	delete s.second;
}

void finish_sessions(std::map<uint64_t, std::pair<std::thread *, http_session_t *> > *const sessions, std::mutex & sessions_lock)
{
	std::vector<uint64_t> delete_these;

	std::unique_lock<std::mutex> lck(sessions_lock);
	for(auto & session: *sessions) {
		if (session.second.second->finished) {
			DOLOG(logger::ll_debug, "Cleaning-up session/thread %" PRIx64, session.first);
			delete_session(session.second);
			delete_these.push_back(session.first);
		}
	}

	for(auto session: delete_these)
		sessions->erase(session);
}

void run_meta(shm_message_queue *const shm_meta,
		std::map<uint64_t, std::pair<std::thread *, http_session_t *> > *const sessions, std::mutex & sessions_lock,
		WOLFSSL_CTX *const ctx)
{
	set_thread_name("run_meta");

	while(!stop_flag) {
		finish_sessions(sessions, sessions_lock);

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
		std::optional<addr_ip4> from_addr;  // peer
		std::optional<int>      from_port;
		std::optional<addr_ip4> to_addr;  // here
		std::optional<int>      to_port;

		for(auto & line: lines) {
			auto parts = split(line, "=");
			DOLOG(logger::ll_debug, "Processing \"%s\"", line.c_str());

			if (parts[0] == "action") {
				if (parts[1] == "close")
					action = close;
				else if (parts[1] == "open")
					action = open;
				else {
					DOLOG(logger::ll_error, "ERR) TCP meta: invalid action \"%s\"", parts[1].c_str());
					invalid = true;
					break;
				}
			}
			else if (parts[0] == "session-id") {
				session_id = my_stoull_hex(parts[1]);
			}
			else if (parts[0] == "from_addr") {
				from_addr = addr_ip4(parts[1], ".", false);
			}
			else if (parts[0] == "from_port") {
				from_port = my_stoi_dec(parts[1]);
			}
			else if (parts[0] == "to_addr") {
				to_addr = addr_ip4(parts[1], ".", false);
			}
			else if (parts[0] == "to_port") {
				to_port = my_stoi_dec(parts[1]);
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
		else if (session_id.has_value() == false) {
			DOLOG(logger::ll_warning, "session id missing in shm command");
		}
		else if (action == close) {
			DOLOG(logger::ll_debug, "\"close\" for %" PRIx64 " received", session_id.value());

			std::unique_lock<std::mutex> lck(sessions_lock);
			auto it = sessions->find(session_id.value());
			if (it != sessions->end()) {
				delete_session(it->second);
				sessions->erase(it);
			}
			else {
				DOLOG(logger::ll_warning, "Session %" PRIx64 " already gone", session_id.value());
			}
		}
		else if (action == open && from_addr.has_value() && from_port.has_value() && to_addr.has_value() && to_port.has_value()) {
			DOLOG(logger::ll_debug, "\"open\" for %" PRIx64 " received", session_id.value());

			// TODO start thread that listens on the new shared memory segment named by the session_id in hex
			// all L7s have an RX and a TX shm
			// tcp has a thread per L7 for L7-TX
			// en/of tcp heeft een queue van L7-TX shm-pointers (zie run_out) die iets te doen hebben <-- hoe wordt die gevuld?

			std::string shm_name_base { std::format("{:x}_", session_id.value()) };
			auto shm_in  = new shm_message_queue(shm_name_base + "rx", 16384);
			shm_in ->begin();  // TODO error handling
			auto shm_to_l7 = new shm_message_queue(shm_name_base + "tx", 16384);
			shm_to_l7->begin();  // TODO error handling

			std::unique_lock<std::mutex> lck(sessions_lock);
			DOLOG(logger::ll_debug, "New session %" PRIx64, session_id.value());
			http_session_t *hs = new http_session_t(
					session_id.value(),
					shm_in, shm_to_l7,
					from_addr.value(), from_port.value(),
					to_addr  .value(), to_port  .value(),
					ctx);
			std::thread *th = new std::thread([hs] { process_http_request(hs); });
			auto rc = sessions->insert({ session_id.value(), { th, hs } });
			if (rc.second == false) {
				hs->stop_flag = true;
				th->join();
				delete th;
				delete hs;
			}
		}
		else {
			DOLOG(logger::ll_warning, "Unexpected state");
		}

		free(m);
	}

	DOLOG(logger::ll_warning, "HTTP meta handler stopping");
}

void run(shm_message_queue *const shm_meta,
	std::map<uint64_t, std::pair<std::thread *, http_session_t *> > *const sessions, std::mutex & sessions_lock,
	WOLFSSL_CTX *const tls_ctx)
{
	std::thread meta([&] { run_meta(shm_meta, sessions, sessions_lock, tls_ctx); });
	meta.join();
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

        wolfSSL_Init();
        wolfSSL_Debugging_ON();

	dictionary *d = iniparser_load(cfg_file.c_str());
	for(int i=0; i<iniparser_getnsec(d); i++) {
		std::string section_name = iniparser_getsecname(d, i);
		if (section_name != "global" && section_name != "specific") {
			fprintf(stderr, "Section \"%s\" in configuration file is unknown\n", section_name.c_str());
			return 1;
		}
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
	int is_tls = iniparser_getboolean(d, "specific:enable-tls", false);
	std::string https_certificate_file = iniparser_getstring(d, "specific:certificate-file", "");
	std::string https_private_key_file = iniparser_getstring(d, "specific:private-key-file", "");
	iniparser_freedict(d);

	signal(SIGINT,  sig_handler);
	signal(SIGTERM, sig_handler);

	shm_message_queue *shm_meta = create_shm(name_meta, msg_queue_size_meta);
	if (shm_meta == nullptr)
		return 1;

	std::map<uint64_t, std::pair<std::thread *, http_session_t *> > sessions;
	std::mutex sessions_lock;

	WOLFSSL_METHOD *method = wolfSSLv23_server_method();
	WOLFSSL_CTX    *ctx    = wolfSSL_CTX_new(method);

	if (is_tls) {
		if (wolfSSL_CTX_use_certificate_file(ctx, https_certificate_file.c_str(), SSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
			fprintf(stderr, "Can't load server cert file\n");
			return 1;
		}

		if (wolfSSL_CTX_use_PrivateKey_file(ctx, https_private_key_file.c_str(), SSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
			fprintf(stderr, "Can't load server private key file\n");
			return 1;
		}

		wolfSSL_SetIORecv(ctx, my_wolfssl_receive);
		wolfSSL_SetIOSend(ctx, my_wolfssl_send   );
	}

	run(shm_meta, &sessions, sessions_lock, is_tls ? ctx : nullptr);

	if (ctx)
		wolfSSL_CTX_free(ctx);

	delete shm_meta;

        wolfSSL_Cleanup();

	return 0;
}
