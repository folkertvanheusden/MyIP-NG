#include <string>

#include "utils/log.h"
#include "utils/shm.h"


shm_message_queue *create_shm(const std::string & name, const size_t size)
{
	if (name.size() >= max_id_length) {
		DOLOG(logger::ll_fatal, "Name \"%s\" for shared memory segment is too long (max %zu)", name.c_str(), max_id_length - 1);
		return nullptr;
	}

	if (size < sizeof(shm_message_queue::message)) {
		DOLOG(logger::ll_fatal, "Size of shared memory segment \"%s\" is too small: %zu bytes, must be at least %zu bytes", name.c_str(), size, sizeof(shm_message_queue::message));
		return nullptr;
	}

	auto *out = new shm_message_queue(name, size);
	if (out == nullptr) {
		DOLOG(logger::ll_fatal, "Failed to instantiate shared memory segment \"%s\"", name.c_str());
		return nullptr;
	}

	if (out->begin() == false) {
		DOLOG(logger::ll_fatal, "Failed to initialize shared memory segment \"%s\"", name.c_str());
		delete out;
		return nullptr;
	}

	return out;
}
