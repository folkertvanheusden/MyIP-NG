// (C) 2021-2023 by Folkert van Heusden <mail@vanheusden.com>
// Released under MIT license

#pragma once

#include <condition_variable>
#include <mutex>
#include <deque>

template <class T>
class queue
{
private:
	std::condition_variable cv;
	mutable std::mutex m;
	std::deque<T> q;

public:
	queue(void)
	{
	}

	~queue(void)
	{
	}

	void push(T t)
	{
		std::lock_guard<std::mutex> lock(m);
		q.push_back(t);
		cv.notify_one();
	}

	T pop(void)
	{
		std::unique_lock<std::mutex> lock(m);
		while(q.empty())
			cv.wait(lock);
		T val = q.front();
		q.pop_front();
		return val;
	}

	std::optional<T> pop(const int timeout)
	{
		auto until = std::chrono::system_clock::now() + std::chrono::milliseconds(timeout);

		std::unique_lock<std::mutex> lock(m);
		while(q.empty()) {
			if (cv.wait_until(lock, until) == std::cv_status::timeout)
				return { };
		}
		T val = q.front();
		q.pop_front();
		return val;
	}

	void unpop(T t)
	{
		std::unique_lock<std::mutex> lock(m);
		q.push_front(t);
	}
};
