#!/usr/bin/env python3

# Given input `TXlQYXNzd29yZA==hacker`, decodes up until `==`.

# References:
# - [Ori Damari on Twitter: \"A small challenge: What is the correct input to print 'you win dude'? https://t.co/Dnd1dl9xRN\" / Twitter](https://twitter.com/0xrepnz/status/1355295649915404291)
# - [base64 — Base16, Base32, Base64, Base85 Data Encodings &\#8212; Python 3\.9\.1 documentation](https://docs.python.org/3/library/base64.html)
#     > It provides encoding and decoding functions for the encodings specified in RFC 3548
# - [RFC 3548 \- The Base16, Base32, and Base64 Data Encodings \- 2.3. Interpretation of non-alphabet characters in encoded data](https://tools.ietf.org/html/rfc3548.html#section-2.3)
#     > If more than the allowed number of pad characters are found at the end of the string, e.g., a base 64 string terminated with "===", the excess pad characters could be ignored.

import base64
import hashlib


def check_password(user_password_base64):
    user_password = base64.b64decode(user_password_base64)
    user_password_hash = hashlib.sha256(user_password).hexdigest()

    my_password = b"MyPassword"
    my_password_hash = hashlib.sha256(my_password).hexdigest()
    if my_password_hash != user_password_hash:
        return

    if "hacker" not in user_password_base64:
        return

    print("you win dude..")
