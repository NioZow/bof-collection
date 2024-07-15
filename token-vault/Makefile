BOF_NAME := token-vault
CC_x64   := x86_64-w64-mingw32-gcc
CC_x86   := i686-w64-mingw32-gcc
SRC      := src/token.c

FLAGS    := -w -Iinclude

all: x64 x86

x86:
	@ echo "[*] Compiling x86 bof"
	@ $(CC_x86) -o bin/$(BOF_NAME).x86.o -Os -c $(SRC) $(FLAGS)

x64:
	@ echo "[*] Compiling x64 bof"
	@ $(CC_x64) -o bin/$(BOF_NAME).x64.o -Os -c $(SRC) $(FLAGS)

clean:
	@ rm -rf bin/*.o
