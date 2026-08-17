#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <queue>
#include <thread>
#include <unistd.h>

#include "gen.h"
#include "time.h"


template <typename T, void (*FreeFunction)(T &)>
class queue
{
private:
	const std::optional<std::pair<int, bool> > max_n_entries;
       	const std::optional<uint64_t>              max_age;
	const int                                  clean_interval;
	std::atomic_bool                           stop_flag   { false   };
	std::thread                               *th_cleaner { nullptr };
	std::mutex                                 data_lock;
	std::condition_variable                    cv_can_get;
	std::condition_variable                    cv_can_put;
	std::map<uint64_t, std::queue<T> >         data;

	void cleaner() {
		int clean_counter = 0;
		while(!stop_flag) {
			if (clean_counter < clean_interval) {
				usleep(100'000);
				continue;
			}
			clean_counter = 0;

			std::unique_lock<std::mutex> lck(data_lock);
			for(auto & group: data) {
				if (max_n_entries.has_value()) {
					while(group.second.size() > max_n_entries.value().first) {
						FreeFunction(group.second.front());
						group.second.pop();
					}
				}

				if (max_age.has_value()) {
					uint64_t now = get_us();

					while(group.second.empty() == false && group.second.front().ts < now - max_age.value()) {
						FreeFunction(group.second.front());
						group.second.pop();
					}
				}
			}
		}
	}

public:
	// clean interval in multiples of 100ms
	queue(const std::optional<std::pair<int, bool> > max_n_entries, const std::optional<uint64_t> max_age, const int clean_interval) :
		max_n_entries (max_n_entries),
		max_age       (max_age      ),
		clean_interval(clean_interval)
	{
		th_cleaner = new std::thread(&queue::cleaner, this);
	}

	virtual ~queue() {
		stop_flag = true;
		th_cleaner->join();
		delete th_cleaner;

		for(auto & group: data) {
			while(group.second.empty() == false) {
				FreeFunction(group.second.front());
				group.second.pop();
			}
		}
	}

	void add_item(const uint64_t key, T & item) {
		std::unique_lock<std::mutex> lck(data_lock);

		auto it = data.find(key);
		if (it == data.end()) {
			it = data.insert({ key, { } }).first;
			it->second.push(item);
			cv_can_get.notify_all();
			return;
		}

		// when full and blocking: wait, else
		// just put and let cleaner take care of it
		if (max_n_entries.has_value() && max_n_entries.value().second) {
			while(it->second.size() >= max_n_entries.value().first)
				cv_can_put.wait_for(lck, std::chrono::milliseconds(SLEEP_INTERVAL_MS));
		}

		it->second.push(item);
		cv_can_get.notify_all();

		cv_can_get.notify_all();
	}

	std::optional<T> get_item(const uint64_t key) {
		std::unique_lock<std::mutex> lck(data_lock);
		auto it = data.find(key);
		if (it == data.end() || it->second.empty())
			return { };

		cv_can_put.notify_one();

		auto item = it->second.front();
		it->second.pop();
		return item;
	}

	std::optional<T> get_item_blocking(const uint64_t key) {
		std::unique_lock<std::mutex> lck(data_lock);

		while(!stop_flag) {
			auto it = data.find(key);
			if (it != data.end() && it->second.empty() == false) {
				cv_can_put.notify_one();

				auto item = it->second.front();
				it->second.pop();
				return item;
			}

			cv_can_get.wait_for(lck, std::chrono::milliseconds(SLEEP_INTERVAL_MS));
		}

		return { };
	}
};
