cmake_minimum_required(VERSION 3.26)
project(Keylogger-Bof C)

set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)

#
# output directory
#
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)

#
# project files
#
file(GLOB_RECURSE IMPERIUM_SRC
        "src/*.c"
)

file(GLOB_RECURSE IMPERIUM_INCLUDE
        "include/*.h"
)

add_executable(${PROJECT_NAME} ${IMPERIUM_SRC} ${IMPERIUM_INCLUDE})

#
# include path
#
include_directories(include)