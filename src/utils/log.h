#pragma once

#include <cerrno>
#include <cstring>
#include <string>


class logger
{
public:
	enum loglevel_t { ll_debug, ll_info, ll_warning, ll_error, ll_fatal };

private:
	loglevel_t  ll       { ll_debug      };
	std::string log_file { "logfile.txt" };

public:
	logger();
	virtual ~logger();

	loglevel_t get_loglevel() const { return ll; }
	void       set_loglevel(const loglevel_t ll);
	void       set_logfile (const std::string & log_file);

	void dolog(const loglevel_t ll, const char *const file, const void *const p, const char *const function, const char *const fmt, ...);
};

extern logger log_;

#define DOLOG(ll, fmt, ...) do {        \
        if (ll >= log_.get_loglevel())  \
                log_.dolog(ll, __FILE__, nullptr, __FUNCTION__, fmt, ##__VA_ARGS__);   \
        } while(0)

#define DOLOG_C(ll, fmt, ...) do {        \
        if (ll >= log_.get_loglevel())  \
                log_.dolog(ll, __FILE__, __builtin_extract_return_addr(__builtin_return_address(0)), __FUNCTION__, fmt, ##__VA_ARGS__);   \
        } while(0)
