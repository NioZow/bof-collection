cmake_minimum_required(VERSION 3.26)
project(Imperium C)

set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)

#
# include path
#
include_directories(include)

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
# targets
#
set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE C)
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "${PROJECT_NAME}.x64.o")