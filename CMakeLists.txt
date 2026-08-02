cmake_minimum_required(VERSION 3.9.4)

project(MyIP-NG3 VERSION 0.1)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_definitions("-D_FILE_OFFSET_BITS=64")

set(CMAKE_BUILD_TYPE Debug)

add_compile_options(-Wall -pedantic)

add_compile_options(-fsanitize=address,undefined)
add_link_options(-fsanitize=address,undefined)

add_library(shm
	src/utils/shm.cpp
)

add_library(log
	src/utils/log.cpp
)

add_executable(shm_test
	src/shm_test.cpp
	)

add_executable(shm_test2
	src/shm_test2.cpp
	src/utils/net.cpp
	src/utils/shm_message.cpp
	)

add_executable(tap_server
	src/utils/net.cpp
	src/utils/shm_message.cpp
	src/tap_server.cpp
	)

add_executable(arp_server
	src/arp_server.cpp
	src/utils/net.cpp
	src/utils/shm_message.cpp
	src/utils/str.cpp
	)

target_link_libraries(shm_test shm log)
target_link_libraries(shm_test2 shm log)
target_link_libraries(arp_server shm log)
target_link_libraries(tap_server shm log)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads)
target_link_libraries(shm_test Threads::Threads)

include(FindPkgConfig)

pkg_check_modules(INI REQUIRED iniparser)
target_link_libraries(tap_server ${INI_LIBRARIES})
target_include_directories(tap_server PUBLIC ${INI_INCLUDE_DIRS})
target_compile_options(tap_server PUBLIC ${INI_CFLAGS_OTHER})
target_link_libraries(arp_server ${INI_LIBRARIES})
target_include_directories(arp_server PUBLIC ${INI_INCLUDE_DIRS})
target_compile_options(arp_server PUBLIC ${INI_CFLAGS_OTHER})
