cmake_minimum_required(VERSION 3.6)
project(hw01)

set(CMAKE_LEGACY_CYGWIN_WIN32 0)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES main.cpp mbedtls/aes.h aes.c mbedtls/ctr_drbg.h ctr_drbg.c entropy.c mbedtls/entropy.h mbedtls/config.h mbedtls/check_config.h)
add_executable(hw01 ${SOURCE_FILES})