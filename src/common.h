#include <string>

#include "utils/shm.h"


shm_message_queue *create_shm(const std::string & name, const size_t size);
