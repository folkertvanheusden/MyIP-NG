#include <cassert>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "log.h"
#include "shm.h"


#define PAD8(x)  (((x) & 7) ? (x) + 8 - ((x) & 7) : (x))

shm_message_queue::shm_message_queue(const std::string & local_identifier, const size_t size):
	local_identifier(local_identifier),
	size(size)
{
	assert(local_identifier.size() < max_id_length);
}

shm_message_queue::~shm_message_queue()
{
	if (get_shm != nullptr && get_shm != MAP_FAILED)
		munmap(get_shm, size);
	if (get_segment != -1)
		close(get_segment);
}

bool shm_message_queue::begin()
{
	if (get_segment != -1)
		return false;

	get_segment = shm_open(local_identifier.c_str(), O_RDWR | O_CREAT, 0600);
	if (get_segment == -1) {
		DOLOG(logger::ll_error, "shm_open(%s) failed: %s", local_identifier.c_str(), strerror(errno));
		return false;
	}

	// check if new
	struct stat segment_stat { };
	if (fstat(get_segment, &segment_stat) == -1) {
		DOLOG(logger::ll_error, "fstat on shm failed: %s", strerror(errno));
		return false;
	}

	auto total_segment_size = size + sizeof(shared_memory);

	bool is_new = segment_stat.st_size != ssize_t(total_segment_size);

	if (is_new) {
		DOLOG(logger::ll_info, "new shared memory segment");

		if (ftruncate(get_segment, total_segment_size) == -1) {
			DOLOG(logger::ll_error, "ftruncate failed: %s", strerror(errno));
			return false;
		}
	}

	get_shm = reinterpret_cast<shared_memory *>(mmap(nullptr, total_segment_size, PROT_READ | PROT_WRITE, MAP_SHARED, get_segment, 0));
	if (get_shm == MAP_FAILED) {
		DOLOG(logger::ll_error, "mmap failed: %s", strerror(errno));
		return false;
	}

	if (is_new) {
		pthread_condattr_t cond_attr { };
		pthread_condattr_init(&cond_attr);
		pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED);
		pthread_cond_init(&get_shm->condition, &cond_attr);
		pthread_condattr_destroy(&cond_attr);

		pthread_mutexattr_t mutex_attr { };
		pthread_mutexattr_init(&mutex_attr);
		pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED);
		pthread_mutexattr_setrobust (&mutex_attr, PTHREAD_MUTEX_ROBUST  );
		pthread_mutex_init(&get_shm->mutex, &mutex_attr);
		pthread_mutexattr_destroy(&mutex_attr);

		get_shm->total_size         = size;
		get_shm->filled             = 0;
		get_shm->most_recent_msg_nr = 0;
	}

	return true;
}

shm_message_queue::message * shm_message_queue::wait_for_message(const int timeout, const msg_type search_type, const std::optional<uint64_t> & msg_nr)
{
	timespec ts { };

	if (timeout >= 0) {
		// the man-page of pthread_cond_timedwait says explicitly to use gettimeofday here
		if (gettimeofday(&tv, nullptr) == -1) {
			DOLOG(logger::ll_error, "gettimeofday failed: %s", strerror(errno));
			return nullptr;
		}

		ts.tv_sec  += timeout / 1000;
		ts.tv_nsec += (timeout % 1000) * 1'000'000;
		while (ts.tv_nsec >= 1'000'000'000) {
			ts.tv_sec++;
			ts.tv_nsec -= 1'000'000'000;
		}
	}

	if (int err = pthread_mutex_lock(&get_shm->mutex); err != 0) {
		if (err == EOWNERDEAD) {
			DOLOG(logger::ll_error, "pthread_mutex_lock returned EOWNERDEAD, \"repairing\" mutex...");
			pthread_mutex_consistent(&get_shm->mutex);
		}
		else {
			DOLOG(logger::ll_error, "pthread_mutex_lock failed: %s", strerror(err));
			return nullptr;
		}
	}

	for(;;) {
		uint8_t *end = &get_shm->data[get_shm->filled];
		uint8_t *cur = &get_shm->data[0];
		while(end - cur >= long(sizeof(message))) {
			message *m      = reinterpret_cast<message *>(cur);
			assert(m->marker == 0xdeadbeef);
			uint32_t length       = m->size;
			size_t   total_length = PAD8(sizeof(message) + length);
			uint64_t cur_msg_nr   = m->msg_nr;
			assert(length > 0);

			if ((m->type == search_type || search_type == msg_any) &&
				(msg_nr.has_value() == false || (msg_nr.has_value() == true && msg_nr.value() == cur_msg_nr))) {
				message *copy = reinterpret_cast<message *>(new uint8_t[total_length]);
				memcpy(copy, m, total_length);

				size_t left = end - cur - total_length;
				assert(size_t(end - cur) >= total_length);
				assert((long(cur) & 7) == 0);
				assert((total_length & 7) == 0);
				if (left)
					memmove(cur, &cur[total_length], left);
				assert(get_shm->filled >= total_length);
				get_shm->filled -= total_length;

				if (int err = pthread_mutex_unlock(&get_shm->mutex); err != 0)
					DOLOG(logger::ll_error, "pthread_mutex_unlock failed: %s", strerror(err));

				return copy;
			}

			cur += total_length;
			assert((long(cur) & 7) == 0);
		}

		if (timeout >= 0) {
			if (int err = pthread_cond_timedwait(&get_shm->condition, &get_shm->mutex, &ts); err != 0) {
				// either an error or timeout
				// unlock when timed out
				if (err != ETIMEDOUT)
					DOLOG(logger::ll_error, "pthread_cond_timedwait failed: %s", strerror(err));
				else if (int err = pthread_mutex_unlock(&get_shm->mutex); err != 0)
					DOLOG(logger::ll_error, "pthread_mutex_unlock failed: %s", strerror(err));
				break;
			}
		}
		else {
			if (int err = pthread_cond_wait(&get_shm->condition, &get_shm->mutex); err != 0) {
				DOLOG(logger::ll_error, "pthread_cond_wait failed: %s", strerror(err));
				break;
			}
		}
	}

	return nullptr;
}

bool shm_message_queue::send_message(const std::string & remote_identifier, message *const m)
{
	uint32_t length            = m->size;
	size_t   total_msg_length  = sizeof(message) + length;
	bool     ok                = false;
	size_t   padded_msg_length = PAD8(total_msg_length);

	assert(m->marker == 0xdeadbeef);
	assert(length > 0);

	m->msg_nr = ++get_shm->most_recent_msg_nr;
	memset(m->sender, 0x00, sizeof(m->sender));
	memcpy(m->sender, local_identifier.c_str(), local_identifier.size());

	if (int err = pthread_mutex_lock(&get_shm->mutex); err != 0) {
		if (err == EOWNERDEAD) {
			DOLOG(logger::ll_error, "pthread_mutex_lock returned EOWNERDEAD, \"repairing\" mutex...");
			pthread_mutex_consistent(&get_shm->mutex);
		}
		else {
			DOLOG(logger::ll_error, "pthread_mutex_lock failed: %s", strerror(err));
			return false;
		}
	}

	if (get_shm->total_size >= get_shm->filled + padded_msg_length) {
		memcpy(&get_shm->data[get_shm->filled], m, total_msg_length);
		get_shm->filled += padded_msg_length;

		if (int err = pthread_cond_broadcast(&get_shm->condition); err != 0) {
			DOLOG(logger::ll_error, "pthread_cond_signal failed: %s", strerror(err));
		}
		else {
			ok = true;
		}
	}
	else {
		DOLOG(logger::ll_warning, "queue for \"%s\" full, dropping message", remote_identifier.c_str());
	}

	if (int err = pthread_mutex_unlock(&get_shm->mutex); err != 0) {
		DOLOG(logger::ll_error, "pthread_mutex_unlock failed: %s", strerror(err));
		return false;
	}

	return ok;
}
