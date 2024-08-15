#!/usr/bin/env python3

import requests
from typing import List

files = ["ntbcd.h", "ntbcd.h", "ntdbg.h", "ntexapi.h", "ntgdi.h", "ntimage.h", "ntioapi.h", "ntkeapi.h", "ntldr.h", "ntlpcapi.h",
         "ntmisc.h", "ntmmapi.h", "ntnls.h", "ntobapi.h", "ntpebteb.h", "ntpfapi.h", "ntpnpapi.h", "ntpoapi.h", "ntpsapi.h",
         "ntregapi.h", "ntrtl.h", "ntsam.h", "ntseapi.h", "ntsmss.h", "ntsxs.h", "nttmapi.h", "nttp.h", "ntwmi.h", "ntwow64.h",
         "ntxcapi.h", "ntzwapi.h", "phnt.h", "phnt_ntdef.h", "phnt_windows.h", "subprocesstag.h", "usermgr.h", "winsta.h"]

base_url = "https://raw.githubusercontent.com/winsiderss/phnt/master/"

class Parser:
    def __init__(self):
        self.output = []

    def include(self, name):
        # include header files

        if name not in files:
            raise Exception(f"can not include file {name}")

        # download the file
        res = requests.get(f"{base_url}{name}")
        if res.status_code != 200:
            raise Exception(f"failed to download file {name}")

        print("hello from include")

        # parse that file
        self.parse(res.text.split("\n"))

    def function_ptr(self, header, i) -> int:

        cnt = i + 1

        # the syscall always ends with the string ");"
        # search for that string
        while True:
            if header[cnt][-2:] == ");":
                # found it now rewrite the structure
                func_name = header[i + 3][:-1]

                self.output.append(
                    f"typedef NTSTATUS ( NTAPI*fn{func_name} )(\n" +
                    f"{'\n'.join(header[i + 4:cnt])}\n" +
                    f"{header[cnt].strip()}\n"
                )

                i = cnt + 1
                break

            cnt += 1

        return i

    def parse(self, header):
        length = len(header)
        i = 0

        while i < length:

            if header[i] == "NTSYSCALLAPI":
                # check if a syscall is been declared
                # rewrite it
                i = self.function_ptr(header, i)
            elif len(header[i]) > 10 and header[i][:9] == "#include ":
                # include the file directly
                self.include(header[i][10:-1])
            else:
                self.output.append(header[i])

            i += 1

    def write(self):
        with open("include/phnt.h", "w") as f:
            f.write("\n".join(self.output))

def main():
    # make a http request to download the file
    res = requests.get("https://raw.githubusercontent.com/winsiderss/phnt/master/ntexapi.h")
    content = res.text.split("\n")

    parser = Parser()
    parser.parse(content)
    parser.write()

if __name__ == '__main__':
    main()