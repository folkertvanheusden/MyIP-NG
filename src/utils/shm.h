#pragma once

#include <cstdint>
#include <optional>
#include <pthread.h>
#include <string>


constexpr const int max_id_length = 32;

class shm_message_queue
{
public:
	struct shared_memory {
		pthread_mutex_t mutex;
		pthread_cond_t  condition_put;
		pthread_cond_t  condition_get;
		size_t          total_size;
		size_t          filled;
		uint64_t        most_recent_msg_nr;
		uint8_t         data[1];
	};

	enum msg_type { msg_new = 1, msg_reply = 2, msg_any = 0 /* msg_any only as parameter to wait */ };
	struct message {
		uint32_t        size;  // by user
		msg_type        type;  // by user
		uint64_t        msg_nr;  // set by shm.cpp
		char            sender[max_id_length];  // set by shm.cpp
		uint8_t         data[1];  // by user
	};

private:
	const std::string local_identifier;
	const size_t      size             {  0      };
	int               get_segment      { -1      };
	shared_memory    *get_shm          { nullptr };

public:
	shm_message_queue(const std::string & local_identifier, const size_t size);
	virtual ~shm_message_queue();

	bool      begin           ();

	// deallocate with free()
	message * wait_for_message(const int timeout /* milliseconds */, const msg_type type, const std::optional<uint64_t> & msg_nr);
	bool      send_message    (const std::string & remote_identifier, message *const m, const bool blocking);
};

shm_message_queue::message *allocate_shm_message(const size_t size);
