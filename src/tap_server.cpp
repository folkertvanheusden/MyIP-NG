#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <poll.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <arpa/inet.h>
#include <iniparser/iniparser.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "utils/gen.h"
#include "utils/log.h"
#include "utils/shm.h"
#include "utils/shm_message.h"


constexpr const uint8_t bc_addr[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

std::atomic_bool stop_flag { false };

void sig_handler(int sig)
{
	stop_flag = true;
}

static void set_ifr_name(ifreq *const ifr, const std::string & device_name)
{
	size_t copy_name_n = std::min(size_t(IFNAMSIZ), device_name.size());
	memcpy(ifr->ifr_name, device_name.c_str(), copy_name_n);
	ifr->ifr_name[copy_name_n] = 0x00;
}

int open_tap(const std::string & device_name, const int mtu_size)
{
	int fd = open("/dev/net/tun", O_RDWR);
	if (fd == -1) {
		DOLOG(logger::ll_error, "open /dev/net/tun failed: %s", strerror(errno));
		return -1;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		DOLOG(logger::ll_error, "fcntl(FD_CLOEXEC) failed: %s", strerror(errno));
		close(fd);
		return -1;
	}

	ifreq ifr_tap { };
	ifr_tap.ifr_flags = IFF_TAP | IFF_NO_PI;
	set_ifr_name(&ifr_tap, device_name);
	if (ioctl(fd, TUNSETIFF, &ifr_tap) == -1) {
		DOLOG(logger::ll_error, "ioctl TUNSETIFF(%s) failed: %s", device_name.c_str(), strerror(errno));
		close(fd);
		return -1;
	}

	// MyIP calcs checksums by itself
	if (ioctl(fd, TUNSETNOCSUM, 1) == -1) {
		DOLOG(logger::ll_error, "ioctl TUNSETNOCSUM: %s", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

bool set_mtu_size(const std::string & device_name, const int mtu_size)
{
	int fd_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd_sock == -1) {
		DOLOG(logger::ll_error, "failed to create socket: %s", strerror(errno));
		return false;
	}

	ifreq ifr_tap { };
	set_ifr_name(&ifr_tap, device_name);
	ifr_tap.ifr_addr.sa_family = AF_INET;
	ifr_tap.ifr_mtu            = mtu_size;
	if (ioctl(fd_sock, SIOCSIFMTU, &ifr_tap) == -1) {
		DOLOG(logger::ll_error, "ioctl SIOCSIFMTU(%d): %s", mtu_size, strerror(errno));
		return false;
	}

	close(fd_sock);

	return true;
}

bool get_local_mac(const std::string & device_name, uint8_t mac_addr[6])
{
	int fd_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd_sock == -1) {
		DOLOG(logger::ll_error, "failed to create socket: %s", strerror(errno));
		return false;
	}

	ifreq ifr_tap { };
	set_ifr_name(&ifr_tap, device_name);
	ifr_tap.ifr_addr.sa_family = AF_INET;
	if (ioctl(fd_sock, SIOCGIFHWADDR, &ifr_tap) == -1) {
		DOLOG(logger::ll_error, "ioctl SIOCGIFHWADDR: %s", strerror(errno));
                return false;
        }

	memcpy(mac_addr, ifr_tap.ifr_hwaddr.sa_data, 6);
	close(fd_sock);

	return true;
}

void load_mappings(std::map<uint16_t, std::string> *const mappings_in, std::map<std::string, uint16_t> *const mappings_out, const dictionary *const d)
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
		uint16_t    k   = std::stoi(col + 1, nullptr, 16);
		mappings_in ->insert({ k, v });
		mappings_out->insert({ v, k });
	}

	delete [] keys;
}

void run_in(shm_message_queue *const shm, const int tap_fd, const uint8_t mac_addr[6], const std::map<uint16_t, std::string> & mappings_in)
{
	pollfd  fds[]       = { { tap_fd, POLLIN, 0 } };
	uint8_t buffer[65536] { };

	while(!stop_flag) {
		int rc = poll(fds, 1, SLEEP_INTERVAL_MS);
		if (rc == -1) {
			if (errno == EINTR)
				continue;

			DOLOG(logger::ll_error, "poll: %s", strerror(errno));
			break;
		}
		if (rc == 0)
			continue;

		int size = read(tap_fd, reinterpret_cast<char *>(buffer), sizeof buffer);
		if (size < 42) {
			DOLOG(logger::ll_debug, "truncated frame (%zu bytes)", size);
			continue;
		}

		DOLOG(logger::ll_debug, "frame of %d bytes received for %02x:%02x:%02x:%02x:%02x:%02x",
				size,
				buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);

		// for us? or broadcast/multicast?
		if ((buffer[0] & 1) == 0 &&  // multicast
		    memcmp(&buffer[0], mac_addr, 6) != 0 &&
		    memcmp(&buffer[0], bc_addr,  6) != 0)
			continue;

		const uint16_t type = (buffer[12] << 8) | buffer[13];
		auto           it   = mappings_in.find(type);
		if (it == mappings_in.end()) {
			DOLOG(logger::ll_debug, "No mapping for %04x", type);
			continue;
		}

		auto *msg = wrap_message(6, &buffer[6],
                                         6, &buffer[0],
                                         size - 14, &buffer[14],
					 { });  // FIXME handle vlan

		if (shm->send_message(it->second, msg, false))
			DOLOG(logger::ll_debug, "Message pushed to shared memory of \"%s\"", it->second.c_str());
		else
			DOLOG(logger::ll_warning, "Could not push message to SHM");

		free(msg);
	}
}

void run_out(shm_message_queue *const shm, const int tap_fd, const uint8_t mac_addr[6], const std::map<std::string, uint16_t> & mappings_out)
{
	while(!stop_flag) {
		shm_message_queue::message *m = shm->wait_for_message(SLEEP_INTERVAL_MS, shm_message_queue::msg_any, { });
		if (!m)
			continue;

		size_t         from_len = 0;
		size_t         to_len   = 0;
		size_t         pl_len   = 0;
		const uint8_t *from     = nullptr;
		const uint8_t *to       = nullptr;
		const uint8_t *pl       = nullptr;
		if (unwrap_message(m, &from_len, &from, &to_len, &to, &pl_len, &pl) == false) {
			DOLOG(logger::ll_error, "Corrupt message in shared memory segment!");
			free(m);
			continue;
		}

		if (from_len != 6 || to_len != 6) {
			DOLOG(logger::ll_error, "Unexpected address lengths!");
			free(m);
			continue;
		}

		if (pl_len == 0) {
			DOLOG(logger::ll_warning, "Empty payload");
			free(m);
			continue;
		}

		auto it = mappings_out.find(m->sender);
		if (it == mappings_out.end()) {
			DOLOG(logger::ll_debug, "No mapping for %s", m->sender);
			free(m);
			continue;
		}

		size_t   packet_length = 6 + 6 + 2 + pl_len;
		uint8_t *packet        = new uint8_t[packet_length];
		memcpy(&packet[0], to,   6);
		memcpy(&packet[6], from, 6);
		packet[12] = it->second >> 8;
		packet[13] = it->second;
		memcpy(&packet[14], pl, pl_len);

		if (write(tap_fd, packet, packet_length) != ssize_t(packet_length)) {
			DOLOG(logger::ll_debug, "Problem sending packet: %s", strerror(errno));
			free(m);
		}
		else {
			DOLOG(logger::ll_debug, "Sent packet of %zu bytes for %s", packet_length, m->sender);
		}

		delete [] packet;

		free(m);
	}
}

void announcer(shm_message_queue *const shm, const uint8_t mac_addr[6], const std::string & announce_mac_name)
{
	const std::string msg = std::format("setmac={0:02x}:{1:02x}:{2:02x}:{3:02x}:{4:02x}:{5:02x}",
				mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
	shm_message_queue::message *m = allocate_shm_message(msg.size());
	m->type = shm_message_queue::msg_new;
	m->size = msg.size();
	memcpy(m->data, msg.c_str(), m->size);

	int i = 0;
	while(!stop_flag) {
		if (++i < 10) {
			usleep(SLEEP_INTERVAL_MS * 1000);
			continue;
		}
		i = 0;

		// announce-mac-name to ARP process
		DOLOG(logger::ll_debug, "Announce \"%s\" to %s", msg.c_str(), announce_mac_name.c_str());
		shm->send_message(announce_mac_name, m, false);
	}

	free(m);
}

void run(shm_message_queue *const shm, const int tap_fd, const uint8_t mac_addr[6],
		const std::map<uint16_t, std::string> & mappings_in,
		const std::map<std::string, uint16_t> & mappings_out,
		const std::string & announce_mac_name)
{
	std::thread rx([&] { run_in (shm, tap_fd, mac_addr, mappings_in ); });
	std::thread tx([&] { run_out(shm, tap_fd, mac_addr, mappings_out); });
	std::thread announce([shm, mac_addr, announce_mac_name] { announcer(shm, mac_addr, announce_mac_name); });
	announce.join();
	tx.join();
	rx.join();
}

int main(int argc, char *argv[])
{
	std::string cfg_file;
	int         c        = -1;
	while((c = getopt(argc, argv, "c:")) != -1) {
		if (c == 'c')
			cfg_file = optarg;
	}

	if (cfg_file.empty()) {
		fprintf(stderr, "Use -c to select a configuration file\n");
		return 1;
	}

	DOLOG(logger::ll_info, "TAP server starting...");

	dictionary *d = iniparser_load(cfg_file.c_str());
	for(int i=0; i<iniparser_getnsec(d); i++) {
		std::string section_name = iniparser_getsecname(d, i);
		if (section_name != "global" && section_name != "specific" && section_name != "mappings") {
			fprintf(stderr, "Section \"%s\" in configuration file is unknown\n", section_name.c_str());
			return 1;
		}
	}
	std::string name     = iniparser_getstring(d, "global:name",  "");
	if (name.empty()) {
		fprintf(stderr, "\"name\" under \"global\" missing\n");
		return 1;
	}
	std::string device_name = iniparser_getstring(d, "specific:dev", "");
	if (device_name.empty()) {
		fprintf(stderr, "\"dev\" under \"specific\" missing\n");
		return 1;
	}
	std::string announce_mac_name = iniparser_getstring(d, "specific:announce-mac-name", "");
	if (announce_mac_name.empty()) {
		fprintf(stderr, "\"announce-mac-name\" under \"specific\" missing\n");
		return 1;
	}
	int msg_queue_size = iniparser_getint(d, "specific:msg-queue-size", 0);
	if (msg_queue_size == 0) {
		msg_queue_size = 16384;
		fprintf(stderr, "Using default msg queue size of %d bytes\n", msg_queue_size);
	}
	int mtu_size       = iniparser_getint(d, "specific:mtu-size",       0);
	if (mtu_size == 0) {
		mtu_size = 1512;
		fprintf(stderr, "Using default MTU size of %d bytes\n", mtu_size);
	}
        int run_as = iniparser_getint(d, "global:run-as", -1);
        if (run_as == -1) {
                fprintf(stderr, "\"run-as\" not set (in \"global\")\n");
                return 1;
        }
	std::map<uint16_t, std::string> mappings_in;
	std::map<std::string, uint16_t> mappings_out;
	load_mappings(&mappings_in, &mappings_out, d);
	iniparser_freedict(d);

	signal(SIGINT, sig_handler);

	int               tap_fd = open_tap(device_name, mtu_size);
	uint8_t           mac_addr[6] { };
	get_local_mac(device_name, mac_addr);
	set_mtu_size (device_name, mtu_size);

	if (setuid(run_as) == -1) {
		fprintf(stderr, "Cannot change user to %d: %s\n", run_as, strerror(errno));
		return 1;
	}

	shm_message_queue shm(name, msg_queue_size);
	if (shm.begin() == false) {
		fprintf(stderr, "Cannot initialize shared memory segment\n");
		return 1;
	}

	run(&shm, tap_fd, mac_addr, mappings_in, mappings_out, announce_mac_name);

	return 0;
}
