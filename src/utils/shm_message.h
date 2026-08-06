#include "shm.h"

// TODO:
//  wrap hele packet maar unwrap geeft dan de pointers etc die de vorige laag zet
//  dan is de hele packet beschikbaar voor icmp

// de-allocate with free()
std::pair<uint8_t *, size_t> wrap_message(const size_t full_pkt_len, const uint8_t *const full_pkt,
		                          const size_t from_len,     const uint8_t *const from,
                                          const size_t to_len,       const uint8_t *const to,
                                          const size_t pl_len,       const uint8_t *const pl);
shm_message_queue::message * wrap_message(const size_t full_pkt_len, const uint8_t *const full_pkt,
		                          const size_t from_len,     const uint8_t *const from,
                                          const size_t to_len,       const uint8_t *const to,
                                          const size_t pl_len,       const uint8_t *const pl,
					  const std::optional<uint64_t> reply_to);

// will not allocate anything
bool unwrap_message(const size_t full_pkt_len, const uint8_t *const full_pkt,
		    size_t *const from_len,    const uint8_t **const from,
                    size_t *const to_len,      const uint8_t **const to,
                    size_t *const pl_len,      const uint8_t **const pl);
bool unwrap_message(const shm_message_queue::message *const m,
		    size_t *const full_pkt_len, const uint8_t **const full_pkt,
		    size_t *const from_len,     const uint8_t **const from,
                    size_t *const to_len,       const uint8_t **const to,
                    size_t *const pl_len,       const uint8_t **const pl);
