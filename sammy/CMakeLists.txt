cmake_minimum_required(VERSION 3.26)
project(sammy C)

set(CMAKE_C_STANDARD 11)
set(MINGW_PATH /nix/store/jmsk2m9ixyx2g3x7dybyc1r92r07fxcz-mingw-w64-x86_64-w64-mingw32-10.0.0-dev/include)

include_directories(${MINGW_PATH})
include_directories(include)

add_executable(sammy src/sammy.c
        include/Native.h
        include/beacon.h
        include/Defs.h
        include/sammy.h
        src/utils.c
)
