#!/usr/bin/env python3
from sys import argv

"""
parse sdk names like the following so those names are easily usable in a C file:

// Token: 0x04003DFA RID: 15866
None = 0U,
// Token: 0x04003E09 RID: 15881
[SDKName("MAXIMUM_ALLOWED")]

...

MaximumAllowed = 33554432U,
// Token: 0x04003E0A RID: 15882
[SDKName("ACCESS_SYSTEM_SECURITY")]
AccessSystemSecurity = 16777216U

"""

if len(argv) != 2:
    print(f"usage: {argv[0]} <filename>")
    exit()

with open(argv[1], "r") as f:
    content = f.readlines()
    sdkName = ""

    # set the first line starting with [SDKNAME] as the base offset
    for line in content: 

        stripped_line = line.strip()

        # ignore comments
        if stripped_line[:2] == "//":
            pass
        elif stripped_line[:8] == "[SDKName":
            sdkName = stripped_line[10:10+stripped_line[10:].index('"')]
        elif stripped_line.count("=") and sdkName != "":

            value = stripped_line.split('=')[1].split(',')[0].strip()
            if value[-1] == "U":
                value = value[:-1]

            print(f"#define {sdkName} {value}")