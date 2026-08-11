cmake_minimum_required(VERSION 3.9.4)

project(MyIP-NG3 VERSION 0.1)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_definitions("-D_FILE_OFFSET_BITS=64")

#set(CMAKE_BUILD_TYPE RelWithDebInfo)
set(CMAKE_BUILD_TYPE Debug)

add_compile_options(-Wall -pedantic)

#add_compile_options(-fsanitize=address,undefined)
#add_link_options(-fsanitize=address,undefined)

add_library(shm
	src/utils/shm.cpp
)

add_library(log
	src/utils/log.cpp
)

add_executable(shm_test
	src/tests/shm_test.cpp
	)

add_executable(shm_dump
	src/tests/shm_dump.cpp
	)

add_executable(addresses_test
	src/tests/addresses_test.cpp
	src/utils/str.cpp
	)

add_executable(shm_message_test
	src/tests/shm_message_test.cpp
	src/utils/net.cpp
	src/utils/shm_message.cpp
	)

add_executable(arp_test
	src/tests/arp_test.cpp
	src/utils/net.cpp
	src/utils/shm_message.cpp
	)

add_executable(checksum_test
	src/tests/checksum_tcp_udp_test.cpp
	src/utils/checksum.cpp
	src/utils/str.cpp
	)

add_executable(tap_server
	src/utils/net.cpp
	src/utils/shm_message.cpp
	src/utils/stoi.cpp
	src/utils/str.cpp
	src/tap_server.cpp
	)

add_executable(promiscuous_server
	src/promisc_server.cpp
	src/utils/net.cpp
	src/utils/shm_message.cpp
	src/utils/stoi.cpp
	src/utils/str.cpp
	)

add_executable(arp_server
	src/arp_server.cpp
	src/utils/net.cpp
	src/utils/shm_message.cpp
	src/utils/str.cpp
	)

add_executable(ip4_server
	src/ip4_server.cpp
	src/utils/checksum.cpp
	src/utils/net.cpp
	src/utils/shm_message.cpp
	src/utils/stoi.cpp
	src/utils/str.cpp
	src/utils/time.cpp
	)

add_executable(icmp_server
	src/icmp_server.cpp
	src/utils/checksum.cpp
	src/utils/net.cpp
	src/utils/shm_message.cpp
	src/utils/str.cpp
	src/utils/time.cpp
	)

add_executable(tcp_server
	src/3dparty/SipHash/siphash.c
	src/tcp_server.cpp
	src/utils/checksum.cpp
	src/utils/net.cpp
	src/utils/shm_message.cpp
	src/utils/str.cpp
	src/utils/stoi.cpp
	src/utils/time.cpp
	)

add_executable(udp_server
	src/udp_server.cpp
	src/utils/checksum.cpp
	src/utils/net.cpp
	src/utils/shm_message.cpp
	src/utils/stoi.cpp
	)

add_executable(ntp_server
	src/ntp_server.cpp
	src/utils/net.cpp
	src/utils/shm_message.cpp
	)

target_link_libraries(addresses_test log)
target_link_libraries(arp_server shm log)
target_link_libraries(arp_test shm log)
target_link_libraries(checksum_test log)
target_link_libraries(icmp_server shm log)
target_link_libraries(ip4_server shm log)
target_link_libraries(ntp_server shm log)
target_link_libraries(promiscuous_server shm log)
target_link_libraries(shm_test shm log)
target_link_libraries(shm_message_test shm log)
target_link_libraries(tap_server shm log)
target_link_libraries(tcp_server shm log)
target_link_libraries(udp_server shm log)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads)
target_link_libraries(shm_test Threads::Threads)

include(FindPkgConfig)

pkg_check_modules(INI REQUIRED iniparser)
target_link_libraries(arp_server ${INI_LIBRARIES})
target_include_directories(arp_server PUBLIC ${INI_INCLUDE_DIRS})
target_compile_options(arp_server PUBLIC ${INI_CFLAGS_OTHER})
target_link_libraries(icmp_server ${INI_LIBRARIES})
target_include_directories(icmp_server PUBLIC ${INI_INCLUDE_DIRS})
target_compile_options(icmp_server PUBLIC ${INI_CFLAGS_OTHER})
target_link_libraries(ip4_server ${INI_LIBRARIES})
target_include_directories(ip4_server PUBLIC ${INI_INCLUDE_DIRS})
target_compile_options(ip4_server PUBLIC ${INI_CFLAGS_OTHER})
target_link_libraries(ntp_server ${INI_LIBRARIES})
target_include_directories(ntp_server PUBLIC ${INI_INCLUDE_DIRS})
target_compile_options(ntp_server PUBLIC ${INI_CFLAGS_OTHER})
target_link_libraries(promiscuous_server ${INI_LIBRARIES})
target_include_directories(promiscuous_server PUBLIC ${INI_INCLUDE_DIRS})
target_compile_options(promiscuous_server PUBLIC ${INI_CFLAGS_OTHER})
target_link_libraries(tap_server ${INI_LIBRARIES})
target_include_directories(tap_server PUBLIC ${INI_INCLUDE_DIRS})
target_compile_options(tap_server PUBLIC ${INI_CFLAGS_OTHER})
target_link_libraries(tcp_server ${INI_LIBRARIES})
target_include_directories(tcp_server PUBLIC ${INI_INCLUDE_DIRS})
target_compile_options(tcp_server PUBLIC ${INI_CFLAGS_OTHER})
target_link_libraries(udp_server ${INI_LIBRARIES})
target_include_directories(udp_server PUBLIC ${INI_INCLUDE_DIRS})
target_compile_options(udp_server PUBLIC ${INI_CFLAGS_OTHER})
