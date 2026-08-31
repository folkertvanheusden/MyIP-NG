#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>


std::optional<int> my_stoi_dec(const std::string & str)
{
	try {
		return std::stoi(str);
	}
	catch(const std::invalid_argument & ia) {
	}

	return { };
}

std::optional<int> my_stoi_hex(const std::string & str)
{
	try {
		return std::stoi(str, nullptr, 16);
	}
	catch(const std::invalid_argument & ia) {
	}

	return { };
}

std::optional<uint64_t> my_stoull_hex(const std::string & str)
{
	try {
		return std::stoull(str, nullptr, 16);
	}
	catch(const std::invalid_argument & ia) {
	}

	return { };
}
