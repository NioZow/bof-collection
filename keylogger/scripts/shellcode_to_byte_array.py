#!/usr/bin/env python3

import argparse

def main():
    parser = argparse.ArgumentParser( description = 'Convert shellcode to c byte array' )
    parser.add_argument( '-f', help='Path to the source shellcode', default="../bin/keylogger.x64.bin" )
    option = parser.parse_args()

    #
    # open the file
    #
    with open(option.f, "rb") as f:
        #
        # read the file
        #
        content = f.read()
        i = 0
        last = len(content) - 1
        print("unsigned char shellcode[] = {")
        for byte in content:
            if i == last:
                print(f"0x{byte:02X}" + " };")
            elif i % 16 != 15:
                print(f"0x{byte:02X},", end=" ")
            else:
                print(f"0x{byte:02X},", end="\n")
            i += 1

if __name__ == "__main__":
    main()
