#!/usr/bin/env python3
from sys import argv
import requests

def parse_msdoc(url: str) -> None:

    # download the doc
    res = requests.get(url)
    if res.status_code != 200:
        raise Exception(f"failed to download the documentation: {res.status_code}")

    content = res.text.split("\n")
    grep_start_string = '<pre><code class="lang-cpp">'
    grep_end_string = '</code></pre>'
    found_code_block = False
    function = []

    # look for the function (the first code block)
    for line in content:

        if line.startswith(grep_end_string):
            break
        elif found_code_block:
            function.append(line)
        elif line.startswith(grep_start_string):
            # found the code block
            function.append(line[len(grep_start_string):])
            found_code_block = True

    if len(function) == 0:
        raise Exception("failed to find the function")

    # rewrite the SAL
    # performance are terrible, i know
    for i in range(len(function)):
        function[i] = function[i].replace("[in] ", "IN ")
        function[i] = function[i].replace("[out] ", "OUT ")
        function[i] = function[i].replace("[in, out] ", "IN OUT ")
        function[i] = function[i].replace("[in, optional] ", "IN OPTIONAL ")
        function[i] = function[i].replace("[out, optional] ", "OUT OPTIONAL ")
        function[i] = function[i].replace("[in, out, optional] ", "IN OUT OPTIONAL ")

    # rewrite as a type
    func_name = function[0].split(" ")[1][:-1]
    func_type = function[0].split(" ")[0]
    function[0] = f"typedef {func_type} (WINAPI*fn{func_name})("

    print(f"DLL: {get_dll_msdoc(content)}")
    print("\n".join(function))

def get_dll_msdoc(content) -> str:

    grep_string = "<td><strong>DLL</strong></td>"
    grep_string_2 = '<td style="text-align: left;">'
    grep_string_3 = '</td>'
    found = False

    for line in content:
        if found:
            return line[len(grep_string_2):-len(grep_string_3)]

        if line.startswith(grep_string):
            found = True

    return "not found"


def main():
    if len(argv) != 2:
        print(f"usage: {argv[0]} <url>")
        return

    url = argv[1]

    if "https://learn.microsoft.com/en-us/windows" in url:
        parse_msdoc(url)


if __name__ == "__main__":
    main()