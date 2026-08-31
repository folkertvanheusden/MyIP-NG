#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>
#include <format>

#include "log.h"
#include "str.h"


constexpr const uint8_t bc_addr[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

struct addr {
	uint8_t *a     { nullptr };
	size_t   a_len { 0       };

	addr() {  // for comparator
	}

	addr(const size_t len_in) {
		a_len = len_in;
		a = new uint8_t[a_len]();
	}

	addr(const std::string & what, const std::string & seperator, const bool is_hex) {
		auto parts = split(what, seperator);
		a_len = parts.size();
		a = new uint8_t[a_len];
		try {
			if (is_hex) {
				for(size_t i=0; i<a_len; i++)
					a[i] = std::stoi(parts[i], nullptr, 16);
			}
			else {
				for(size_t i=0; i<a_len; i++)
					a[i] = std::stoi(parts[i]);
			}
		}
		catch(const std::invalid_argument & ia) {
			DOLOG(logger::ll_error, "Cannot convert string \"%s\" to a list of values: %s", what.c_str(), ia.what());
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

	bool operator!=(const addr & input) const {
		return memcmp(a, input.a, a_len) != 0;
	}

	bool operator==(const addr & input) const {
		return memcmp(a, input.a, a_len) == 0;
	}

	addr & operator=(const addr & input) {
		delete [] a;
		a = new uint8_t[input.a_len];
		memcpy(a, input.a, input.a_len);
		a_len = input.a_len;
		return *this;
	}

	bool operator()(const addr & a, const addr & b) const {
		return memcmp(a.a, b.a, a.a_len) < 0;
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

	const uint8_t *get() const {
		return a;
	}

	size_t length() const {
		return a_len;
	}
};

typedef addr addr_ip4;
typedef addr addr_mac;
