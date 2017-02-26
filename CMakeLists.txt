cmake_minimum_required(VERSION 3.6)
project(hw01)

set(CMAKE_LEGACY_CYGWIN_WIN32 0)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(HEADERS_TLS mbedtls/timing.h mbedtls/sha512.h mbedtls/aes.h mbedtls/aesni.h mbedtls/check_config.h mbedtls/config.h mbedtls/ctr_drbg.h mbedtls/entropy.h mbedtls/entropy_poll.h mbedtls/padlock.h mbedtls/platform.h mbedtls/platform_time.h)
set(SOURCES_TLS aes.c aesni.c ctr_drbg.c entropy.c entropy_poll.c platform.c timing.c sha512.c)
set(SOURCE_FILES main.cpp ${HEADERS_TLS} ${SOURCES_TLS})
add_executable(hw01 ${SOURCE_FILES})