#pragma once

#include <cstdint>
#include <cstring>

#include "str.h"


constexpr const uint8_t bc_addr[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

struct addr {
	uint8_t *a     { nullptr };
	size_t   a_len { 0       };

	addr() {  // for comparator
	}

	addr(const std::string & what, const std::string & seperator, const bool is_hex) {
		auto parts = split(what, seperator);
		a_len = parts.size();
		a = new uint8_t[a_len];
		if (is_hex) {
			for(size_t i=0; i<a_len; i++)
				a[i] = std::stoi(parts[i], nullptr, 16);
		}
		else {
			for(size_t i=0; i<a_len; i++)
				a[i] = std::stoi(parts[i]);
		}
	}

	addr(const uint8_t data[], const size_t data_len) {
		a = new uint8_t[data_len];
		memcpy(a, data, data_len);
		a_len = data_len;
	}

	addr(const addr & in) {
		a_len = in.a_len;
		a = new uint8_t[a_len];
		memcpy(a, in.a, a_len);
	}

	virtual ~addr() {
		delete [] a;
	}

	addr & operator=(const addr & input) {
		a = new uint8_t[input.a_len];
		memcpy(a, input.a, input.a_len);
		a_len = input.a_len;
		return *this;
	}

	bool operator()(const addr & lhs, const addr & rhs) const {
		assert(lhs.a_len == rhs.a_len);
		return memcmp(lhs.a, rhs.a, a_len);
	}

	std::string to_str(const char splitter, const bool hex) const {
		std::string out;
		for(size_t i=0; i<a_len; i++) {
			if (i)
				out += splitter;
			out += hex ? std::format("{0:02x}", a[i]) : std::to_string(a[i]);
		}
		return out;
	}

	void get(uint8_t *const p) const {
		assert(a);
		assert(a_len);
		memcpy(p, a, a_len);
	}
};

typedef addr addr_ip4;
typedef addr addr_mac;
