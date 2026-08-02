#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <arpa/inet.h>
#include <iniparser/iniparser.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "log.h"
#include "shm.h"


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
		return -1;
	}

	ifreq ifr_tap1 { };
	ifr_tap1.ifr_flags = IFF_TAP | IFF_NO_PI;
	set_ifr_name(&ifr_tap1, device_name);
	if (ioctl(fd, TUNSETIFF, &ifr_tap1) == -1) {
		DOLOG(logger::ll_error, "ioctl TUNSETIFF(%s) failed: %s", device_name.c_str(), strerror(errno));
		return -1;
	}

	// MyIP calcs checksums by itself
	if (ioctl(fd, TUNSETNOCSUM, 1) == -1) {
		DOLOG(logger::ll_error, "ioctl TUNSETNOCSUM: %s", strerror(errno));
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

	ifreq ifr_tap2 { };
	set_ifr_name(&ifr_tap2, device_name);
	ifr_tap2.ifr_addr.sa_family = AF_INET;
	ifr_tap2.ifr_mtu            = mtu_size;
	if (ioctl(fd_sock, SIOCSIFMTU, &ifr_tap2) == -1) {
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

	ifreq ifr_tap2 { };
	set_ifr_name(&ifr_tap2, device_name);
	ifr_tap2.ifr_addr.sa_family = AF_INET;
	if (ioctl(fd_sock, SIOCGIFHWADDR, &ifr_tap2) == -1) {
		DOLOG(logger::ll_error, "ioctl SIOCGIFHWADDR: %s", strerror(errno));
                return false;
        }

	memcpy(mac_addr, ifr_tap2.ifr_hwaddr.sa_data, 6);
	close(fd_sock);

	return true;
}

void run(shm_message_queue *const shm, const int tap_fd, const uint8_t mac_addr[6])
{
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
	iniparser_freedict(d);

	shm_message_queue shm(name, msg_queue_size);
	int               tap_fd = open_tap(device_name, mtu_size);
	uint8_t mac_addr[6] { };
	get_local_mac(device_name, mac_addr);
	set_mtu_size (device_name, mtu_size);

	run(&shm, tap_fd, mac_addr);

	return 0;
}
