#include <cassert>
#include <cstring>

#include "net.h"
#include "shm.h"


struct wrapped {
	size_t  full_pkt_len;
	size_t  from_offset;
	size_t  from_len;
	size_t  to_offset;
	size_t  to_len;
	size_t  pl_offset;
	size_t  pl_len;
	uint8_t full_pkt[0];
} __attribute__((__packed__));

std::pair<uint8_t *, size_t> wrap_message(const size_t full_pkt_len, const uint8_t *const full_pkt,
		                          const size_t from_len,     const uint8_t *const from,
                                          const size_t to_len,       const uint8_t *const to,
                                          const size_t pl_len,       const uint8_t *const pl)
{
	size_t   total_length = sizeof(wrapped) + full_pkt_len;
	uint8_t *data         = reinterpret_cast<uint8_t *>(malloc(total_length));
	wrapped *p            = reinterpret_cast<wrapped *>(data);

	p->from_offset  = from - full_pkt;
	p->from_len     = from_len;
	p->to_offset    = to - full_pkt;
	p->to_len       = to_len;
	p->pl_offset    = pl - full_pkt;
	p->pl_len       = pl_len;
	p->full_pkt_len = full_pkt_len;
	memcpy(p->full_pkt, full_pkt, full_pkt_len);

	return { data, total_length };
}

shm_message_queue::message * wrap_message(const size_t full_pkt_len, const uint8_t *const full_pkt,
		                          const size_t from_len,     const uint8_t *const from,
                                          const size_t to_len,       const uint8_t *const to,
                                          const size_t pl_len,       const uint8_t *const pl,
					  const std::optional<uint64_t> reply_to)
{
	auto encoded = wrap_message(full_pkt_len, full_pkt, from_len, from, to_len, to, pl_len, pl);
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

bool unwrap_message(const std::pair<const uint8_t *, size_t> & in,
		    size_t *const full_pkt_len, const uint8_t **const full_pkt,
		    size_t *const from_len,     const uint8_t **const from,
                    size_t *const to_len,       const uint8_t **const to,
                    size_t *const pl_len,       const uint8_t **const pl)
{
	const wrapped *p = reinterpret_cast<const wrapped *>(in.first);

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

bool unwrap_message(const shm_message_queue::message *const m,
		    size_t *const full_pkt_len, const uint8_t **const full_pkt,
		    size_t *const from_len,     const uint8_t **const from,
                    size_t *const to_len,       const uint8_t **const to,
                    size_t *const pl_len,       const uint8_t **const pl)
{
	return unwrap_message({ m->data, m->size }, 
		    full_pkt_len, full_pkt,
		    from_len,     from,
                    to_len,       to,
                    pl_len,       pl);
}
