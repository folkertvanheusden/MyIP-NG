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

void logger::set_logfile(const std::string & log_file)
{
	this->log_file = log_file;
}

void logger::dolog(const logger::loglevel_t ll, const char *const file, const void *const p, const char *const function, const char *const fmt, ...)
{
	auto  now        = std::chrono::system_clock::now();
	char *log_buffer = nullptr;

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
		oss << now << " " << last_lf << " [" << p << "] [" << function << "] " << log_buffer << std::endl;
	else
		oss << now << " " << last_lf << " [" << function << "] " << log_buffer << std::endl;
	std::string buffer { oss.str() };

	std::ofstream fh(log_file, std::ios::out | std::ios::app);
	fh << buffer;
	fh.close();

	std::cout << buffer;

	free(log_buffer);
}

logger log_;
