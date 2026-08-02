#include <cstring>

#include "shm.h"


shm_message_queue::message * wrap_message(const size_t from_len, const uint8_t *const from,
                                          const size_t to_len,   const uint8_t *const to,
                                          const size_t pl_len,   const uint8_t *const pl)
{
	size_t   total_pl_length = 2 + from_len + 2 + to_len + 4 + pl_len;
	size_t   total_length    = sizeof(shm_message_queue::message) + total_pl_length;
	shm_message_queue::message *msg = reinterpret_cast<shm_message_queue::message *>(calloc(1, total_length));
	uint8_t *payload         = reinterpret_cast<uint8_t *>(msg->data);
	size_t   offset          = 0;

	msg->size = total_pl_length;

	payload[offset++] = to_len >> 8;
	payload[offset++] = to_len;
	memcpy(&payload[offset], to, to_len);
	offset += to_len;

	payload[offset++] = from_len >> 8;
	payload[offset++] = from_len;
	memcpy(&payload[offset], from, from_len);
	offset += from_len;

	payload[offset++] = pl_len >> 24;
	payload[offset++] = pl_len >> 16;
	payload[offset++] = pl_len >>  8;
	payload[offset++] = pl_len;
	memcpy(&payload[offset], pl, pl_len);
	offset += pl_len;

	return msg;
}
