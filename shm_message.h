#include "shm.h"

// de-allocate with free()
shm_message_queue::message * wrap_message(const size_t from_len, const uint8_t *const from,
                                          const size_t to_len,   const uint8_t *const to,
                                          const size_t pl_len,   const uint8_t *const pl,
					  const bool   is_reply);
