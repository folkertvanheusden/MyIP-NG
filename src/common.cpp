#include <cstdint>
#include <map>
#include <string>
#include <iniparser/iniparser.h>

#include "utils/log.h"
#include "utils/shm.h"
#include "utils/stoi.h"


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

void load_mappings_single(std::map<uint16_t, std::string> *const mappings_in, const dictionary *const d)
{
	constexpr const char section_name[] = "mappings";
	int n_keys = iniparser_getsecnkeys(d, section_name);
	if (n_keys == 0)
		return;
	const char **keys = new const char *[n_keys]();
	iniparser_getseckeys(d, section_name, keys);

	for(int i=0; i<n_keys; i++) {
		const char *col = strchr(keys[i], ':');  // unless inilib is broken
		const char *v   = iniparser_getstring(d, keys[i], "");
		if (strlen(v) == 0) {
			fprintf(stderr, "Mapping \"%s\" is invalid\n", keys[i]);
			exit(1);
		}
		auto k = my_stoi_dec(col + 1);
		if (k.has_value() == false)
			exit(1);
		mappings_in->insert({ k.value(), v });
	}

	delete [] keys;
}

void load_mappings_duo(std::map<uint16_t, std::string> *const mappings_in, std::map<std::string, uint16_t> *const mappings_out, const dictionary *const d)
{
	constexpr const char section_name[] = "mappings";
	int n_keys = iniparser_getsecnkeys(d, section_name);
	if (n_keys == 0)
		return;
	const char **keys = new const char *[n_keys]();
	iniparser_getseckeys(d, section_name, keys);

	for(int i=0; i<n_keys; i++) {
		const char *col = strchr(keys[i], ':');  // unless inilib is broken
		const char *v   = iniparser_getstring(d, keys[i], "");
		if (strlen(v) == 0) {
			fprintf(stderr, "Mapping \"%s\" is invalid\n", keys[i]);
			exit(1);
		}
		auto k = my_stoi_hex(col + 1);
		if (k.has_value() == false)
			exit(1);
		mappings_in ->insert({ k.value(), v });
		mappings_out->insert({ v, k.value() });
	}

	delete [] keys;
}
