#include <cassert>
#include <cstring>

#include "net.h"
#include "shm.h"


shm_message_queue::message * wrap_message(const size_t from_len, const uint8_t *const from,
                                          const size_t to_len,   const uint8_t *const to,
                                          const size_t pl_len,   const uint8_t *const pl,
					  const std::optional<uint64_t> reply_to)
{
	size_t   total_pl_length = 2 + from_len + 2 + to_len + 4 + pl_len;
	shm_message_queue::message *msg = allocate_shm_message(total_pl_length);
	uint8_t *payload         = reinterpret_cast<uint8_t *>(msg->data);
	size_t   offset          = 0;

	msg->size = total_pl_length;
	if (reply_to.has_value()) {
		msg->msg_nr = reply_to.value();
		msg->type   = shm_message_queue::msg_reply;
	}
	else {
		msg->type   = shm_message_queue::msg_new;
	}

	payload[offset++] = from_len >> 8;
	payload[offset++] = from_len;
	memcpy(&payload[offset], from, from_len);
	offset += from_len;

	payload[offset++] = to_len >> 8;
	payload[offset++] = to_len;
	memcpy(&payload[offset], to, to_len);
	offset += to_len;

	payload[offset++] = pl_len >> 24;
	payload[offset++] = pl_len >> 16;
	payload[offset++] = pl_len >>  8;
	payload[offset++] = pl_len;
	memcpy(&payload[offset], pl, pl_len);
	offset += pl_len;

	assert(offset == total_pl_length);

	return msg;
}

bool unwrap_message(const shm_message_queue::message *const m,
		    size_t *const from_len, const uint8_t **const from,
                    size_t *const to_len,   const uint8_t **const to,
                    size_t *const pl_len,   const uint8_t **const pl)
{
	const uint8_t *payload = m->data;
	size_t         offset  = 0;

	if (offset + 2 >= m->size)
		return false;
	*from_len = get_uint16(&payload[offset]);
	offset += 2;
	if (offset + *from_len >= m->size)
		return false;
	*from = &payload[offset];
	offset += *from_len;

	if (offset + 2 >= m->size)
		return false;
	*to_len = get_uint16(&payload[offset]);
	offset += 2;
	if (offset + *to_len >= m->size)
		return false;
	*to = &payload[offset];
	offset += *to_len;

	if (offset + 4 >= m->size)
		return false;
	*pl_len = get_uint32(&payload[offset]);
	offset += 4;
	if (offset + *pl_len > m->size)  // not a typo
		return false;
	*pl = &payload[offset];

	return true;
}
