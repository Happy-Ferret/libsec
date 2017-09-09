cmake_minimum_required(VERSION 2.6)

project(libsec)

add_library(sec libsec.c)

option (ASAN "Build with ASAN" OFF)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -W -Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith -Wconversion -std=gnu99")

IF (ASAN)
    set(DEBUG 1)
    set(CMAKE_C_COMPILER "clang")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
ENDIF (ASAN)

IF (DEBUG)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O1")
ELSE (DEBUG)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native -Ofast -DNDEBUG")
ENDIF (DEBUG)