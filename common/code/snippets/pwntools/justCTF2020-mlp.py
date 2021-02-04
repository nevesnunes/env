#!/usr/bin/env python3

from pwn import *
import re
import signal


class timeout:
    def __init__(self, seconds=1, error_message="Timeout"):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        signal.alarm(0)


try:
    import colorama
    colorama.init()
    def highlight(text):
        return colorama.Fore.RED + colorama.Style.BRIGHT + str(text) + colorama.Style.RESET_ALL
except ImportError:
    def highlight(text):
        return str(text)


def new_remote():
    return remote("mylittlepwny.nc.jctf.pro", 1337)


r = new_remote()
prompt = b"> "
r.recvregex(prompt, timeout=3)

# for i in range(255):
for i in range(32, 127, 1):
    print(i, bytes([i]))

    res = b''
    r.sendline(chr(i))
    try:
        with timeout(3):
            res = r.recvregex(prompt, timeout=3)
    except TimeoutError:
        res += r.clean(0)
        r = new_remote()
    if not res:
        r = new_remote()
        r.sendline(chr(i))
        try:
            with timeout(3):
                res = r.recvregex(prompt, timeout=3)
        except TimeoutError:
            res += r.clean(0)
            r = new_remote()

    print(highlight(b"\n".join(res.split(b"\n")[:3])))
    for match in re.finditer(b"<(.*)>", res):
        print(highlight(match.group(1)))
