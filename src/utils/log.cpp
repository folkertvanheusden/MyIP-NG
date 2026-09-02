#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <ostream>
#include <sstream>
#include <thread>

#include "log.h"
#include "time.h"


logger::logger()
{
}

logger::~logger()
{
}

void logger::set_loglevel(const loglevel_t ll)
{
	this->ll = ll;
}

void logger::set_loglevel(const std::string & ll)
{
	if (ll == "debug")
		this->ll = ll_debug;
	else if (ll == "trace")
		this->ll = ll_trace;
	else if (ll == "info")
		this->ll = ll_info;
	else if (ll == "warning")
		this->ll = ll_warning;
	else if (ll == "error")
		this->ll = ll_error;
	else if (ll == "fatal")
		this->ll = ll_fatal;
}

void logger::set_logfile(const std::string & log_file)
{
	this->log_file = log_file;
}

void logger::dolog(const logger::loglevel_t ll, const char *const file, const void *const p, const char *const function, const char *const fmt, ...)
{
	auto  now        = std::chrono::system_clock::now();
	char *log_buffer = nullptr;

	constexpr const char *const ll_str[] {
			"TRC",
			"DBG",
			"INF",
			"WRN",
			"ERR",
			"FTL"
	};

	va_list ap;
	va_start(ap, fmt);
	int rc = vasprintf(&log_buffer, fmt, ap);
	va_end(ap);
	if (rc == -1) {
		perror("vasprintf");
		exit(1);
	}

	const char *last_lf = strrchr(file, '/');
	if (last_lf)
		last_lf++;
	else
		last_lf = file;

	std::ostringstream oss;
	if (p)
		oss << now << " " << ll_str[ll] << " " << last_lf << " [" << p << "] [" << function << "] " << log_buffer << std::endl;
	else
		oss << now << " " << ll_str[ll] << " " << last_lf << " [" << function << "] " << log_buffer << std::endl;
	std::string buffer { oss.str() };

	std::ofstream fh(log_file, std::ios::out | std::ios::app);
	fh << buffer;
	fh.close();

	std::cout << buffer;

	free(log_buffer);
}

logger log_;

void set_thread_name(std::string name)
{
	if (name.length() > 15)
		name = name.substr(0, 15);

#if defined(__APPLE__)
	pthread_setname_np(name.c_str());
#else
	pthread_setname_np(pthread_self(), name.c_str());
#endif
}
