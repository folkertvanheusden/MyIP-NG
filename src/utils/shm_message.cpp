#include <cassert>
#include <cstring>

#include "net.h"
#include "shm.h"


struct wrapped_up {
	uint32_t type;  // 0xdeadbeef
	size_t  full_pkt_len;
	size_t  from_offset;
	size_t  from_len;
	size_t  to_offset;
	size_t  to_len;
	size_t  pl_offset;
	size_t  pl_len;
	uint8_t full_pkt[0];
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
	size_t      total_length = sizeof(wrapped_up) + full_pkt_len;
	uint8_t    *data         = reinterpret_cast<uint8_t *>(malloc(total_length));
	wrapped_up *p            = reinterpret_cast<wrapped_up *>(data);

	p->type         = 0xdeadbeef;
	p->from_offset  = from - full_pkt;
	assert(p->from_offset <= full_pkt_len - from_len);
	p->from_len     = from_len;
	p->to_offset    = to - full_pkt;
	assert(p->to_offset <= full_pkt_len - to_len);
	p->to_len       = to_len;
	p->pl_offset    = pl - full_pkt;
	assert(p->pl_offset <= full_pkt_len - pl_len);
	p->pl_len       = pl_len;
	p->full_pkt_len = full_pkt_len;
	memcpy(p->full_pkt, full_pkt, full_pkt_len);

	return { data, total_length };
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

	*from_len =  p->from_len;
	*from     = &p->full_pkt[p->from_offset];

	*to_len =  p->to_len;
	*to     = &p->full_pkt[p->to_offset];

	*pl_len =  p->pl_len;
	*pl     = &p->full_pkt[p->pl_offset];

	*full_pkt_len = p->full_pkt_len;
	*full_pkt     = p->full_pkt;

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

	*from_len =  p->from_len;
	*from     = &p->data[0];

	*to_len =  p->to_len;
	*to     = &p->data[*from_len];

	*pl_len =  p->pl_len;
	*pl     = &p->data[*from_len + *to_len];

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
