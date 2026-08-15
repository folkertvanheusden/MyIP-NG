#include <cstdint>
#include <optional>
#include <string>


std::optional<int> my_stoi_dec(const std::string & str);
std::optional<int> my_stoi_hex(const std::string & str);
std::optional<uint64_t> my_stoull_hex(const std::string & str);
