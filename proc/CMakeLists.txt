cmake_minimum_required(VERSION 3.28)
project(proc C)

set(CMAKE_C_STANDARD 17)

include_directories(include)

add_executable(proc src/proc.c
        include/Defs.h
        include/Native.h
        include/beacon.h
        include/Proc.h
        src/utils.c
        src/beacon.c
)
