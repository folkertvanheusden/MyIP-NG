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
#include <turbojpeg.h>
#include <arpa/inet.h>
#include <iniparser/iniparser.h>
#include <sys/stat.h>
#include <zlib.h>

#include "common.h"
#include "font.h"
#include "tcp.h"
#include "utils/addresses.h"
#include "utils/gen.h"
#include "utils/log.h"
#include "utils/net.h"
#include "utils/queue.h"
#include "utils/shm.h"
#include "utils/shm_message.h"
#include "utils/stoi.h"
#include "utils/time.h"


typedef enum {
	vs_initial_handshake_server_send = 0,
	vs_initial_handshake_client_resp,
	vs_security_handshake_server,
	vs_security_handshake_client_resp,
	vs_client_init,
	vs_server_init,
	vs_running_waiting_cmd,
	vs_running_waiting_data,
	vs_running_waiting_data_extra,
	vs_running_waiting_data_ignore,
	vs_terminate
} vnc_state_t;

struct vnc_session_t
{
	const uint64_t    session_id;
	const std::string out_name;
	shm_message_queue *const shm;
	const addr_ip4    from;
	const uint16_t    from_port;
	const addr_ip4    to;
	const uint16_t    to_port;

	std::atomic_bool  finished  { false };
	std::atomic_bool  stop_flag { false };
	queue<std::vector<uint8_t> > incoming;

	vnc_state_t       state { vs_initial_handshake_server_send };
	uint32_t          prev_zsize { };
	z_stream          strm  { };
	tjhandle          jpeg_compressor {};
	uint8_t           depth { 8 };

	vnc_session_t(const uint64_t session_id, const std::string & out_name,
		shm_message_queue *const shm,
		const addr_ip4 from, const uint16_t from_port,
		const addr_ip4 to,   const uint16_t to_port):
		session_id(session_id), out_name(out_name), shm(shm),
		from(from), from_port(from_port),
		to  (to  ), to_port  (to_port  )
	{
	}
};

std::atomic_bool stop_flag { false };

void sig_handler(int sig)
{
	stop_flag = true;
}

struct frame_buffer
{
	int        w        { 0       };
	int        h        { 0       };

        std::mutex fb_lock;
	uint8_t   *buffer   { nullptr };
};

void draw_text(frame_buffer *fb_in, int x, int y, const char *const text, const int r, const int g, const int b)
{
	const int maxo = fb_in->w * fb_in->h * 3;
	int       len  = strlen(text);

	for(int i=0; i<len; i++) {
		int c = text[i] & 127;

		for(int cy=0; cy<8; cy++) {
			for(int cx=0; cx<8; cx++) {
				int o = (cy + y) * fb_in -> w * 3 + (x + i * 8 + cx) * 3;
				if (o >= maxo)
					break;

				uint8_t pixel_value = font_8x8[c][cy][cx];

				fb_in->buffer[o + 0] = pixel_value ? r : 0;
				fb_in->buffer[o + 1] = pixel_value ? g : 0;
				fb_in->buffer[o + 2] = pixel_value ? b : 0;
			}
		}
	}
}

void run_fb(frame_buffer *const fb_work)
{
	set_thread_name("vnc-draw");

	char text[16] { 0 };

	int x  = fb_work->w / 2;
	int y  = fb_work->h / 2;
	int dx = 1;
	int dy = 1;

	uint64_t latest_update = 0;

	while(!stop_flag) {
		// bounce
		x += dx;
		y += dy;

		if (x >= fb_work->w) {
			x = fb_work->w - 1;
			dx = -((rand() % 3) + 1);
		}

		if (y >= fb_work->h) {
			y = fb_work->h - 1;
			dy = -((rand() % 3) + 1);
		}

		if (x < 0) {
			x = 0;
			dx = (rand() % 3) + 1;
		}

		if (y < 0) {
			y = 0;
			dy = (rand() % 3) + 1;
		}

		uint64_t now = get_us();

		if (now - latest_update >= 999999) {  // 1 time per second
			latest_update = now;

			int    subn = (rand() % 5) + 1;
			time_t tnow = time(nullptr);
			tm     tm { 0 };
			gmtime_r(&tnow, &tm);

			for(int y=0; y<fb_work->h; y++) {
				const int o = y * fb_work->w * 3;

				for(int x=0; x<fb_work->w; x++) {
					int ox = o + x * 3;

					if (fb_work->buffer[ox] >= subn)
						fb_work->buffer[ox] -= subn;
				}
			}

			snprintf(text, sizeof text, "%02d:%02d:%02d - MyIP", tm.tm_hour, tm.tm_min, tm.tm_sec);
			draw_text(fb_work, x, y, text, 255, 255, 255);

			fb_work->fb_lock.unlock();
		}

		usleep(SLEEP_INTERVAL_MS);
	}
}

void fin_func(vnc_session_t *const session)
{
	shm_message_queue::message *end_msg = allocate_shm_message(12);
	memcpy(&end_msg->data[0], &session->session_id, 8);
	uint32_t flags = MI_TCP_FIN;
	memcpy(&end_msg->data[8], &flags, 4);

	if (session->shm->send_message(session->out_name, end_msg, true) == false)
		DOLOG(logger::ll_warning, "Cannot send FIN message to %s", session->out_name.c_str());

	free(end_msg);
}

int send_func(vnc_session_t *const session, const uint8_t *const from, const size_t n)
{
	int rc = -1;

	shm_message_queue::message *data_msg = allocate_shm_message(12 + n);
	memcpy(&data_msg->data[0], &session->session_id, 8);
	uint32_t flags = 0;
	memcpy(&data_msg->data[8], &flags, 4);
	memcpy(&data_msg->data[12], from, n);

	if (session->shm->send_message(session->out_name, data_msg, true) == false)
		DOLOG(logger::ll_warning, "Cannot send VNC data to %s", session->out_name.c_str());
	else
		rc = n;

	free(data_msg);

	return rc;
}

int recv_func(vnc_session_t *const session, uint8_t *const to, const size_t n)
{
	if (n == 0)
		return 0;

	uint8_t *p    = to;
	size_t   todo = n;
	do {
		auto   values = session->incoming.pop();
		size_t v_n    = values.size();
		memcpy(p, values.data(), std::min(todo, v_n));

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

inline void encode_pixel(uint8_t *const out, int *const o, const int depth, const uint8_t r, const uint8_t g, const uint8_t b)
{
	if (depth == 32 || depth == 24) {
		out[(*o)++] = b;  // blue
		out[(*o)++] = g;  // green
		out[(*o)++] = r;  // red
		out[(*o)++] = 255;  // alpha
	}
	else if (depth == 8) {
		out[(*o)++] = (r & 0xe0) |  // red
			((g >> 3) & 0x1c) |  // green
			(b >> 6);  // blue
	}
}

// assumes w & h multiples of 16
void hextile(uint8_t *const out, int *const o, const uint8_t *const in, const int w, const int h, const int depth)
{
	for(int y=0; y<h; y += 16) {
		for(int x=0; x<w; x += 16) {
			// see if solid color
			uint8_t sr = in[y * w * 3 + x * 3 + 0];  // solid rgb
			uint8_t sg = in[y * w * 3 + x * 3 + 1];
			uint8_t sb = in[y * w * 3 + x * 3 + 2];

			bool different = false;
			for(int ty=0; ty<16; ty++) {
				int y_offset = (y + ty) * w * 3;

				for(int tx=0; tx<16; tx++) {
					int x_offset = (x + tx) * 3;

					uint8_t csr = in[y_offset + x_offset + 0];  // current solid rgb
					uint8_t csg = in[y_offset + x_offset + 1];
					uint8_t csb = in[y_offset + x_offset + 2];

					if (csr != sr || csg != sg || csb != sb) {
						different = true;
						goto finish_tile_scan;
					}
				}
			}
		finish_tile_scan:

			if (different) {
				out[(*o)++] = 1;  // raw

				for(int ty=0; ty<16; ty++) {
					int y_offset = (y + ty) * w * 3;

					for(int tx=0; tx<16; tx++) {
						int x_offset = (x + tx) * 3;

						uint8_t csr = in[y_offset + x_offset + 0];  // current solid rgb
						uint8_t csg = in[y_offset + x_offset + 1];
						uint8_t csb = in[y_offset + x_offset + 2];

						encode_pixel(out, o, depth, csr, csg, csb);
					}
				}
			}
			else {
				out[(*o)++] = 2;  // background color specified

				encode_pixel(out, o, depth, sr, sg, sb);
			}
		}
	}
}

std::pair<uint8_t *, size_t> calculate_fb_update(frame_buffer *fb, std::vector<int32_t> & encodings,
		bool incremental, int x, int y, int w, int h, uint8_t depth,
		vnc_session_t *const session)
{
	if (fb->w < x + w || fb->h < y + h)
		return { nullptr, 0 };

	int32_t ce = 0;  // RAW is default
	for(int32_t e : encodings) {
		if (e == 5) {  // Hextile
			ce = e;
			DOLOG(logger::ll_debug, "VNC: hextile encoding");
			break;
		}

		if (e == 6) {  // ZLIB
			ce = e;
			DOLOG(logger::ll_debug, "VNC: zlib encoding");
			break;
		}

		if (e == 21) {   // JPEG
			ce = e;
			DOLOG(logger::ll_debug, "VNC: jpeg encoding");
			break;
		}
	}

	uint8_t *message = new uint8_t[4 + 12 * 1 + w * h * 4]; // at most

	message[0] = 0;  // FramebufferUpdate
	message[1] = 0;  // padding
	message[2] = 0;  // number of rectangles
	message[3] = 1;  //  (1)

	message[4] = x >> 8;  // x
	message[5] = x & 255; 
	message[6] = y >> 8;  // y
	message[7] = y & 255; 
	message[8] = w >> 8;  // w
	message[9] = w & 255; 
	message[10] = h >> 8;  // h
	message[11] = h & 255; 
	message[12] = ce >> 24;  // encoding type
	message[13] = ce >> 16;  // (0 == raw)
	message[14] = ce >>  8;
	message[15] = ce;

	uint8_t *temp = nullptr;
	int otemp = 0;

	if (ce != 5 && ce != 21) {
		temp = new uint8_t[w * h * 3 * 2];

		if (depth == 32 || depth == 24) {
			for(int yo=y; yo<y + h; yo++) {
				for(int xo=x; xo<x + w; xo++) {
					int offset = yo * w * 3 + xo * 3;

					temp[otemp++] = fb->buffer[offset + 2];  // blue
					temp[otemp++] = fb->buffer[offset + 1];  // green
					temp[otemp++] = fb->buffer[offset + 0];  // red
					temp[otemp++] = 255;  // alpha
				}
			}
		}
		else if (depth == 8) {
			for(int yo=y; yo<y + h; yo++) {
				for(int xo=x; xo<x + w; xo++) {
					int offset = yo * w * 3 + xo * 3;

					temp[otemp++] = (fb->buffer[offset + 0] & 0xe0) |  // red
							((fb->buffer[offset + 1] >> 3) & 0x1c) |  // green
							(fb->buffer[offset + 2] >> 6);  // blue
				}
			}
		}
		else if (depth == 1) {
			uint8_t b_out = 0, b_n = 0;

			for(int yo=y; yo<y + h; yo++) {
				for(int xo=x; xo<x + w; xo++) {
					int offset = yo * w * 3 + xo * 3;

					int gray = (fb->buffer[offset + 0] + fb->buffer[offset + 1] + fb->buffer[offset + 2]) / 3;
					uint8_t bit = gray >= 128;

					b_out <<= 1;
					b_out |= bit;
					b_n++;

					if (b_n == 8) {
						temp[otemp++] = b_out;
						b_n = 0;
					}
				}
			}

			if (b_n)
				DOLOG(logger::ll_error, "VNC: BITS LEFT: %d", b_n);
		}
		else {
			DOLOG(logger::ll_info, "VNC: depth=%d not supported", depth);
		}
	}

	int o = 16;

	if (ce == 0) {  // raw
		memcpy(&message[o], temp, otemp);
		o += otemp;
	}
	else if (ce == 5) {  // Hextile
		hextile(message, &o, fb->buffer, w, h, depth);
	}
	else if (ce == 6) {  // zlib
		session->strm.next_in   = temp;
		session->strm.avail_in  = otemp;
		session->strm.next_out  = &message[o + 4];
		session->strm.avail_out = w * h * 3 * 2;

		if (deflate(&session->strm, Z_SYNC_FLUSH) != Z_OK)
			DOLOG(logger::ll_warning, "VNC: deflate failed");

		uint32_t size = session->strm.total_out - session->prev_zsize;
		message[o + 0] = size >> 24;
		message[o + 1] = size >> 16;
		message[o + 2] = size >>  8;
		message[o + 3] = size;

		o += size + 4;

		session->prev_zsize = session->strm.total_out;
	}
	else if (ce == 21) {   // jpeg
		uint8_t          *out = nullptr;
		unsigned long int len = 0;
		if (tjCompress2(session->jpeg_compressor, fb->buffer, w, 0, h, TJPF_RGB, &out, &len, TJSAMP_444, 75, TJFLAG_FASTDCT) == -1)
			DOLOG(logger::ll_warning, "VNC: Failed compressing JPEG frame: %s (%dx%d @ %d)", tjGetErrorStr(), w, h, 75);

		memcpy(&message[o], out, len);
		o += len;

		free(out);
	}
	else {
		DOLOG(logger::ll_error, "VNC: unknown encoding type %d", ce);
	}

	delete [] temp;

	return { message, o };
}

uint8_t *recv_alloc(vnc_session_t *const session, const size_t n)
{
	uint8_t *out = new uint8_t[n];
	int rc = recv_func(session, out, n);
	if (rc == -1) {
		delete [] out;
		return nullptr;
	}
	return out;
}

void process_vnc_request(vnc_session_t *const session, frame_buffer *const fb)
{
	set_thread_name("vnc-session");

	DOLOG(logger::ll_debug, "VNC handler running for session %" PRIx64, session->session_id);

	session->jpeg_compressor = tjInitCompress();

	if (deflateInit(&session->strm, Z_DEFAULT_COMPRESSION) != Z_OK)
		DOLOG(logger::ll_warning, "VNC: zlib init failed");
	
	std::vector<int32_t> encodings;
	encodings.push_back(0);  // at least raw

	int  n_encodings        = -1;

	int running_cmd   = -1;
	int ignore_data_n = -1;

	while(!stop_flag) {
		bool cont_or_initial_upd_frame = false;

		DOLOG(logger::ll_debug, "VNC: state: %d", session->state);

		if (session->state == vs_initial_handshake_server_send) {
			constexpr const char initial_message[] = "RFB 003.008\n";

			DOLOG(logger::ll_debug, "VNC: send handshake of 12 bytes");
			if (send_func(session, reinterpret_cast<const uint8_t *>(initial_message), 12) == -1)  // must be 12 bytes
				break;

			session->state = vs_initial_handshake_client_resp;
		}
	
		if (session->state == vs_initial_handshake_client_resp) {
			const char *handshake = reinterpret_cast<const char *>(recv_alloc(session, 12));
			if (!handshake)
				break;

			std::string handshake_str = std::string(handshake, 12);

			if (memcmp(handshake, "RFB", 3) == 0) {  // let's not be too picky
				DOLOG(logger::ll_debug, "VNC: Client responded with protocol version: %s", handshake_str.c_str());
				delete [] handshake;
				session->state = vs_security_handshake_server;
			}
			else {
				DOLOG(logger::ll_info, "VNC: Unexpected/invalid protocol version: %s", handshake_str.c_str());
				delete [] handshake;
				break;
			}
		}

		if (session->state == vs_security_handshake_server) {
			uint8_t message[] = { 1,  // number of security types
				1,  // 'None'
			};

			DOLOG(logger::ll_debug, "VNC: ack security types, %zu bytes", sizeof message);
			if (send_func(session, message, sizeof message) == -1)
				break;

			session->state = vs_security_handshake_client_resp;
		}

		if (session->state == vs_security_handshake_client_resp) {
			const uint8_t *chosen_sec = recv_alloc(session, 1);
			if (!chosen_sec)
				break;

			int cs = *chosen_sec;
			delete [] chosen_sec;

			if (cs == 1) {  // must have chosen security type 'None'
				uint8_t response[] = { 0, 0, 0, 0 };  // OK
				DOLOG(logger::ll_debug, "VNC: Valid security type chosen, %zu bytes", sizeof response);
				if (send_func(session, response, sizeof response) == -1)
					break;
				session->state = vs_client_init;
			}
			else {
				uint8_t response[] = { 0, 0, 0, 1 };  // failed
				DOLOG(logger::ll_info, "VNC: Unexpected/invalid security type: %d (%zu bytes)", cs, sizeof response);
				send_func(session, response, sizeof response);
				break;
			}
		}

		if (session->state == vs_client_init) {
			const uint8_t *client_init = recv_alloc(session, 1);
			if (!client_init)
				break;

			DOLOG(logger::ll_debug, "VNC: client asks for %sdesktop sharing", *client_init ? "" : "NO ");
			session->state = vs_server_init;
			delete [] client_init;
		}

		if (session->state == vs_server_init) {  // 7.3.2
			uint8_t message[] = {
				uint8_t(fb->w >> 8), uint8_t(fb->w & 255),
				uint8_t(fb->h >> 8), uint8_t(fb->h & 255),
				// PIXEL_FORMAT
				32,  // bits per pixel
				24,  // depth
				1,  // big-endian flag
				1,  // true color flag
				0, 255,  // red max
				0, 255,  // green max
				0, 255,  // blue max
				16,  // red shift
				8,  // green shift
				0,  // blue shift (note that alpha is stored in the lowest byte)
				0, 0, 0,
				// name length/string
				0, 0, 0, 7,
				'M', 'y', 'I', 'P', '-', 'N', 'G'  // no "...": that would include a 0x00
			};

			DOLOG(logger::ll_debug, "VNC: server init, %zu bytes", sizeof message);
			if (send_func(session, message, sizeof message) == -1)
				break;

			session->state = vs_running_waiting_cmd;
		}

		if (cont_or_initial_upd_frame) {
			// send initial frame
			auto [ fb_message, fb_message_len ] = calculate_fb_update(fb, encodings, false, 0, 0, fb->w, fb->h, 24, session);
			if (fb_message) {
				DOLOG(logger::ll_debug, "VNC: intial (full) framebuffer update (%zu bytes)", fb_message_len);
				if (send_func(session, fb_message, fb_message_len) == -1)
					break;
				delete [] fb_message;
			}
		}

		if (session->state == vs_running_waiting_cmd) {
			const uint8_t *cmd = recv_alloc(session, 1);
			if (!cmd)
				break;

			running_cmd = *cmd;
			DOLOG(logger::ll_debug, "VNC: Received command %d", running_cmd);
			session->state = vs_running_waiting_data;

			delete [] cmd;
		}

		if (session->state == vs_running_waiting_data) {
			bool proceed = false;
			int ignore_n = 0;

			DOLOG(logger::ll_debug, "VNC: waiting for data for command %d", running_cmd);

			if (running_cmd == 0) {  // SetPixelFormat, 7.5.1
				DOLOG(logger::ll_debug, "VNC: Retrieving pixelformat");

				uint8_t *pf = recv_alloc(session, 19);
				if (!pf)
					break;

				const uint8_t *data = &pf[3];  // skip padding

				session->depth = data[1];

				uint16_t rmax = (data[4] << 8) | data[5];
				uint16_t gmax = (data[6] << 8) | data[7];
				uint16_t bmax = (data[8] << 8) | data[9];

				DOLOG(logger::ll_debug, "VNC: Changed 'depth' (BPP) to %d (bpp: %d, red/green/blue max: %d/%d/%d)", session->depth, data[0], rmax, gmax, bmax);

				session->state = vs_running_waiting_cmd;
				delete [] pf;
			}
			else if (running_cmd == 2) {  // SetEncodings, 7.5.2
				uint8_t *parameters = recv_alloc(session, 3);

				if (!parameters)
					break;
				n_encodings = (parameters[1] << 8) | parameters[2];
				DOLOG(logger::ll_debug, "VNC: Retrieving number of encodings (%d)", n_encodings);
				session->state = vs_running_waiting_data_extra;
				delete [] parameters;
			}
			else if (running_cmd == 3) {  // FramebufferUpdateRequest
				uint8_t *parameters  = recv_alloc(session, 9);
				if (!parameters)
					break;
				bool     incremental = parameters[0];
				int      x = (parameters[1] << 8) | parameters[2];
				int      y = (parameters[3] << 8) | parameters[4];
				int      w = (parameters[5] << 8) | parameters[6];
				int      h = (parameters[7] << 8) | parameters[8];
				auto [ fb_message, fb_message_len ] = calculate_fb_update(fb, encodings, incremental, x, y, w, h, session->depth, session);
				DOLOG(logger::ll_debug, "VNC: framebuffer update for %dx%d at %d,%d: %zu bytes%s",
						w, h, x, y, fb_message_len, incremental?" (incremental)":"");
				if (send_func(session, fb_message, fb_message_len) == -1)
					break;
				delete [] fb_message;
				delete [] parameters;

				proceed = true;
			}
			else if (running_cmd == 4) {  // KeyEvent
				ignore_n = 7;
				DOLOG(logger::ll_debug, "VNC: CLIENT KeyEvent (ignore %d)", ignore_n);
			}
			else if (running_cmd == 5) {  // PointerEvent
				ignore_n = 5;
				DOLOG(logger::ll_debug, "VNC: CLIENT PointerEvent (ignore %d)", ignore_n);
			}
			else if (running_cmd == 6) {  // ClientCutText
				uint8_t *parameters = recv_alloc(session, 7);
				if (!parameters)
					break;

				ignore_data_n = (parameters[3] << 24) | (parameters[4] << 16) | (parameters[5] << 8) | parameters[6];
				DOLOG(logger::ll_debug, "VNC: ClientCutText (ignore %d)", ignore_data_n);

				session->state = vs_running_waiting_data_ignore;
				delete [] parameters;
			}
			else {
				DOLOG(logger::ll_warning, "VNC: Command %d not known (data state)", running_cmd);
				break;
			}

			// part of the command
			if (ignore_n) {
				DOLOG(logger::ll_debug, "VNC: Ignore %d bytes from command", ignore_n);

				uint8_t *ignore = recv_alloc(session, ignore_n);
				if (!ignore)
					break;
				delete [] ignore;
				proceed = true;
			}

			if (proceed) {
				session->state = vs_running_waiting_cmd;
				running_cmd = -1;
			}
		}

		// parameters of a command to ignore
		if (session->state == vs_running_waiting_data_ignore) {
			DOLOG(logger::ll_debug, "VNC: Ignore %d command parameters", ignore_data_n);

			assert(ignore_data_n > 0);
			uint8_t *ignore = recv_alloc(session, ignore_data_n);
			if (!ignore)
				break;

			session->state = vs_running_waiting_cmd;
			ignore_data_n = -1;
			delete [] ignore;
		}

		if (session->state == vs_running_waiting_data_extra) {
			if (running_cmd == 2) {  // SetEncodings
				DOLOG(logger::ll_debug, "VNC: Retrieving %d encodings", n_encodings);

				uint8_t *encodings_bin = recv_alloc(session, n_encodings * 4);
				if (!encodings_bin)
					break;

				encodings.clear();
				for(int i=0; i<n_encodings; i++) {
					int o = i * 4;
					int32_t e = (encodings_bin[o + 0] << 24) | (encodings_bin[o + 1] << 16) | (encodings_bin[o + 2] << 8) | encodings_bin[o + 3] | encodings_bin[o + 3];
					encodings.push_back(e);
					DOLOG(logger::ll_debug, "VNC: encoding %d: %d", i, e);
				}
				n_encodings = -1;

				session->state = vs_running_waiting_cmd;

				delete [] encodings_bin;
			}
			else {
				DOLOG(logger::ll_warning, "VNC: Command %d not known (data-extra state)", running_cmd);
				break;
			}
		}
	}

	fin_func(session);

	DOLOG(logger::ll_info, "VNC: Thread terminating");

	tjDestroy(session->jpeg_compressor);

	deflateEnd(&session->strm);

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
		std::map<uint64_t, std::pair<std::thread *, vnc_session_t *> > *const sessions, std::mutex & sessions_lock,
		shm_message_queue *const shm_meta,
		frame_buffer *const fb)
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

		vnc_session_t *hs = nullptr;
		{
			std::unique_lock<std::mutex> lck(sessions_lock);
			auto it = sessions->find(session_id);
			if (it == sessions->end()) {
				if (flags & MI_TCP_OPEN) {
					DOLOG(logger::ll_debug, "Session %" PRIx64 " not known - new session", session_id);
					hs = new vnc_session_t(
							session_id, out_name, shm,
							addr_ip4(from, from_len), from_port,
							addr_ip4(to, to_len), to_port);
					std::thread *th = new std::thread([hs, fb] { process_vnc_request(hs, fb); });
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
			DOLOG(logger::ll_warning, "VNC session %" PRIx64 " not found", session_id);

		free(m);
	}
}

void run_meta(shm_message_queue *const shm_meta, std::map<uint64_t, std::pair<std::thread *, vnc_session_t *> > *const sessions, std::mutex & sessions_lock)
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

	DOLOG(logger::ll_warning, "VNC meta handler stopping");
}

void run(shm_message_queue *const shm, const std::string & out_name,
		shm_message_queue *const shm_meta,
		std::map<uint64_t, std::pair<std::thread *, vnc_session_t *> > *const sessions, std::mutex & sessions_lock,
		frame_buffer *const fb)
{
	std::thread rx  ([&] { run_in  (shm, out_name, sessions, sessions_lock, shm_meta, fb); });
	std::thread meta([&] { run_meta(shm_meta,      sessions, sessions_lock); });
	std::thread fbr ([&] { run_fb  (fb); });
	fbr.join();
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

	DOLOG(logger::ll_info, "VNC server starting...");

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
	iniparser_freedict(d);

	signal(SIGINT, sig_handler);

	shm_message_queue *shm = create_shm(name, msg_queue_size);
	if (shm == nullptr)
		return 1;

	shm_message_queue *shm_meta = create_shm(name_meta, msg_queue_size_meta);
	if (shm_meta == nullptr)
		return 1;

	std::map<uint64_t, std::pair<std::thread *, vnc_session_t *> > sessions;
	std::mutex sessions_lock;

	frame_buffer fb{};
	fb.w = 640;
	fb.h = 480;
	fb.buffer = new uint8_t[fb.w * fb.h * 3]();

	run(shm, out_name, shm_meta, &sessions, sessions_lock, &fb);

	delete [] fb.buffer;

	delete shm_meta;
	delete shm;

	return 0;
}
