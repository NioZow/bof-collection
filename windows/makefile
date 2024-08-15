MAKEFLAGS += "-s -j 16"

##
## Project name
##
Project := windows

##
## Compilers
##
CC_X64	:= x86_64-w64-mingw32-gcc

##
## defines
##
DEFINES := -DIMPERIUM_DEBUG

##
## Compiler flags
##
CFLAGS := -Iinclude -w -Os -c ${DEFINES}

##
## Stardust source and object files
##
SRC := src/Windows.c

##
## x64 binaries
##
BOF-X64	:= bin/$(Project).x64.o

##
## main target
##
all: x64

x64: clean
	@ echo "[+] compile x64 bof"
	@ $(CC_X64) $(SRC) -o $(BOF-X64) $(CFLAGS)

##
## Clean object files and other binaries
##
clean:
	@ rm -rf bin/obj/*.o bin/*.bin bin/*.exe