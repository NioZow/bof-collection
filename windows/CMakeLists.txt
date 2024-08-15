cmake_minimum_required(VERSION 3.26)
project(Imperium CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)

#
# Compiler flags
#
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Os -fno-asynchronous-unwind-tables -nostdlib")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-ident -fpack-struct=8 -falign-functions=1")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s -ffunction-sections -falign-jumps=1 -w")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -falign-labels=1 -fPIC -Wl,-Tscripts/Linker.ld")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wl,-s,--no-seh,--enable-stdcall-fixup")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -masm=intel -fpermissive -mrdrnd")

#
# include path
#
include_directories(include)

#
# compile defintions
#
add_compile_definitions(IMPERIUM_DEBUG)

#
# output directory
#
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)

#
# project files
#
file(GLOB_RECURSE IMPERIUM_SRC
        "src/*.cc"
)

file(GLOB_RECURSE IMPERIUM_INCLUDE
        "include/common/*.h"
        "include/*.h"
)

add_executable(${PROJECT_NAME} ${IMPERIUM_SRC} ${IMPERIUM_INCLUDE}
        src/Program.cc)

#
# targets
#
set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "${PROJECT_NAME}.x64.bin")