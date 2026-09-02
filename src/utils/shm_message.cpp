#include <cassert>
#include <cstring>

#include "net.h"
#include "shm.h"


struct wrapped_up {
	uint32_t type;  // 0xdeadbeef
	size_t  full_pkt_len;
	size_t  from_len;
	size_t  to_len;
	size_t  pl_len;
	uint8_t data[0];
} __attribute__((__packed__));

struct wrapped_up_tcp {
	uint32_t type;  // 0xdeadbeef
	uint64_t session_id;
	size_t   from_len;
	uint16_t from_port;
	size_t   to_len;
	uint16_t to_port;
	uint32_t flags;
	size_t   pl_len;
	uint8_t  data[0];
} __attribute__((__packed__));

struct wrapped_down {
	uint32_t type;  // 0xbeefdead
	size_t  from_len;
	size_t  to_len;
	size_t  pl_len;
	uint8_t data[0];  // from, to, pl
} __attribute__((__packed__));

std::pair<uint8_t *, size_t> wrap_message_up(
		const size_t full_pkt_len, const uint8_t *const full_pkt,
		const size_t from_len,     const uint8_t *const from,
		const size_t to_len,       const uint8_t *const to,
		const size_t pl_len,       const uint8_t *const pl)
{
	size_t      total_length = sizeof(wrapped_up) + from_len + to_len + pl_len + full_pkt_len;
	uint8_t    *data         = reinterpret_cast<uint8_t *>(malloc(total_length));
	wrapped_up *p            = reinterpret_cast<wrapped_up *>(data);

	p->type         = 0xdeadbeef;
	p->full_pkt_len = full_pkt_len;
	p->from_len     = from_len;
	p->to_len       = to_len;
	p->pl_len       = pl_len;
	memcpy(&p->data[0],                          from,     from_len    );
	memcpy(&p->data[from_len],                   to,       to_len      );
	memcpy(&p->data[from_len + to_len],          pl,       pl_len      );
	memcpy(&p->data[from_len + to_len + pl_len], full_pkt, full_pkt_len);

	return { data, total_length };
}

shm_message_queue::message * wrap_message_up_tcp(
					  const uint64_t session_id, 
		                          const size_t   from_len,     const uint8_t *const from,
					  const uint16_t from_port,
                                          const size_t   to_len,       const uint8_t *const to,
					  const uint16_t to_port,
					  const uint32_t flags,
                                          const size_t   pl_len,       const uint8_t *const pl)
{
	size_t   total_length = sizeof(wrapped_up_tcp) + from_len + to_len + pl_len;
	shm_message_queue::message *msg = allocate_shm_message(total_length);
	auto    *p            = reinterpret_cast<wrapped_up_tcp *>(msg->data);

	p->type         = 0xdeadbeef;
	p->from_len     = from_len;
	p->from_port    = from_port;
	p->to_len       = to_len;
	p->to_port      = to_port;
	p->flags        = flags;
	p->pl_len       = pl_len;
	p->session_id   = session_id;
	memcpy(&p->data[0],                          from,     from_len    );
	memcpy(&p->data[from_len],                   to,       to_len      );
	memcpy(&p->data[from_len + to_len],          pl,       pl_len      );

	return msg;
}

shm_message_queue::message * wrap_message_up(
		const size_t full_pkt_len, const uint8_t *const full_pkt,
		const size_t from_len,     const uint8_t *const from,
		const size_t to_len,       const uint8_t *const to,
		const size_t pl_len,       const uint8_t *const pl,
		const std::optional<uint64_t> reply_to)
{
	auto encoded = wrap_message_up(full_pkt_len, full_pkt, from_len, from, to_len, to, pl_len, pl);
	shm_message_queue::message *msg = allocate_shm_message(encoded.second);

	msg->size = encoded.second;
	if (reply_to.has_value()) {
		msg->msg_nr = reply_to.value();
		msg->type   = shm_message_queue::msg_reply;
	}
	else {
		msg->type   = shm_message_queue::msg_new;
	}

	memcpy(msg->data, encoded.first, msg->size);
	free(encoded.first);

	return msg;
}

bool unwrap_message_up(
		const std::pair<const uint8_t *, size_t> & in,
		size_t *const full_pkt_len, const uint8_t **const full_pkt,
		size_t *const from_len,     const uint8_t **const from,
		size_t *const to_len,       const uint8_t **const to,
		size_t *const pl_len,       const uint8_t **const pl)
{
	const wrapped_up *p = reinterpret_cast<const wrapped_up *>(in.first);
	assert(p->type == 0xdeadbeef);

	*from_len =  p->from_len;
	*from     = &p->data[0];

	*to_len   =  p->to_len;
	*to       = &p->data[*from_len];

	*pl_len   =  p->pl_len;
	*pl       = &p->data[*from_len + *to_len];

	*full_pkt_len =  p->full_pkt_len;
	*full_pkt     = &p->data[*from_len + *to_len + *pl_len];

	return true;
}

bool unwrap_message_up_tcp(
		    const shm_message_queue::message *const m,
		    uint64_t *const session_id,
		    size_t *const   from_len,     const uint8_t **const from,
		    uint16_t *const from_port,
                    size_t *const   to_len,       const uint8_t **const to,
		    uint16_t *const to_port,
		    uint32_t *const flags,
                    size_t *const   pl_len,       const uint8_t **const pl)
{
	const wrapped_up_tcp *p = reinterpret_cast<const wrapped_up_tcp *>(m->data);
	assert(p->type == 0xdeadbeef);

	*session_id = p->session_id;

	*from_len   =  p->from_len;
	*from       = &p->data[0];
	*from_port  = p->from_port;

	*to_len     =  p->to_len;
	*to         = &p->data[*from_len];
	*to_port    = p->to_port;

	*flags      = p->flags;

	*pl_len     =  p->pl_len;
	*pl         = &p->data[*from_len + *to_len];

	return true;
}

bool unwrap_message_up(
		const shm_message_queue::message *const m,
		size_t *const full_pkt_len, const uint8_t **const full_pkt,
		size_t *const from_len,     const uint8_t **const from,
		size_t *const to_len,       const uint8_t **const to,
		size_t *const pl_len,       const uint8_t **const pl)
{
	return unwrap_message_up({ m->data, m->size }, 
		    full_pkt_len, full_pkt,
		    from_len,     from,
                    to_len,       to,
                    pl_len,       pl);
}

// #####

std::pair<uint8_t *, size_t> wrap_message_down(
		const size_t from_len,     const uint8_t *const from,
		const size_t to_len,       const uint8_t *const to,
		const size_t pl_len,       const uint8_t *const pl)
{
	size_t        total_length = sizeof(wrapped_down) + from_len + to_len + pl_len;
	uint8_t      *data         = reinterpret_cast<uint8_t *>(malloc(total_length));
	wrapped_down *p            = reinterpret_cast<wrapped_down *>(data);

	p->type     = 0xbeefdead;
	p->from_len = from_len;
	p->to_len   = to_len;
	p->pl_len   = pl_len;
	memcpy(&p->data[0],                 from, from_len);
	memcpy(&p->data[from_len],          to,   to_len  );
	memcpy(&p->data[from_len + to_len], pl,   pl_len  );

	return { data, total_length };
}

shm_message_queue::message * wrap_message_down(
		const size_t from_len,     const uint8_t *const from,
		const size_t to_len,       const uint8_t *const to,
		const size_t pl_len,       const uint8_t *const pl,
		const std::optional<uint64_t> reply_to)
{
	auto encoded = wrap_message_down(from_len, from, to_len, to, pl_len, pl);
	shm_message_queue::message *msg = allocate_shm_message(encoded.second);

	msg->size = encoded.second;
	if (reply_to.has_value()) {
		msg->msg_nr = reply_to.value();
		msg->type   = shm_message_queue::msg_reply;
	}
	else {
		msg->type   = shm_message_queue::msg_new;
	}

	memcpy(msg->data, encoded.first, msg->size);
	free(encoded.first);

	return msg;
}

bool unwrap_message_down(
		const std::pair<const uint8_t *, size_t> & in,
		size_t *const from_len,     const uint8_t **const from,
		size_t *const to_len,       const uint8_t **const to,
		size_t *const pl_len,       const uint8_t **const pl)
{
	const wrapped_down *p = reinterpret_cast<const wrapped_down *>(in.first);
	assert(p->type == 0xbeefdead);

	*from_len =  p->from_len;
	*from     = &p->data[0];

	*to_len   =  p->to_len;
	*to       = &p->data[*from_len];

	*pl_len   =  p->pl_len;
	*pl       = &p->data[*from_len + *to_len];

	return true;
}

bool unwrap_message_down(
		const shm_message_queue::message *const m,
		size_t *const from_len,     const uint8_t **const from,
		size_t *const to_len,       const uint8_t **const to,
		size_t *const pl_len,       const uint8_t **const pl)
{
	return unwrap_message_down({ m->data, m->size }, 
		    from_len,     from,
                    to_len,       to,
                    pl_len,       pl);
}
