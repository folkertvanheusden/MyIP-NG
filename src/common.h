#include <cstdint>
#include <map>
#include <string>
#if defined(__FreeBSD__)
#include <iniparser.h>
#else
#include <iniparser/iniparser.h>
#endif

#include "utils/shm.h"


shm_message_queue *create_shm(const std::string & name, const size_t size);

void load_mappings_single(std::map<uint16_t, std::string> *const mappings_in, const dictionary *const d);
void load_mappings_duo(std::map<uint16_t, std::string> *const mappings_in, std::map<std::string, uint16_t> *const mappings_out, const dictionary *const d);
