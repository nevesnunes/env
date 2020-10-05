#!/usr/bin/env python3

import sys
import time
import getpass
import paramiko
import string

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('109.233.57.94',
            username='dockesc',
            password='B9Go9eGS')
shell = ssh.invoke_shell()
# shell.settimeout(0.25)

# shell.send('picocom /dev/ttyS0\n')
while True:
    recv = shell.recv(10000)
    if 'Sleeping.'.encode('utf-8') in recv:
        print('got sleeping!')
        break

known_message = '\x10pictur'

while True:
    for i in string.ascii_letters:
        for l in known_message:
            shell.send(l)
            time.sleep(0.07)

        shell.send(i)
        time.sleep(0.1)

        if shell.recv_ready():
            print(f'not an {known_message}{i}')
            sys.stdout.buffer.write(shell.recv(1000) + '\n'.encode('utf-8'))
            sys.stdout.buffer.flush()
            continue

        known_message = known_message + i
        print(f'its an {i}! known message so far: {known_message}')

        # reset
        shell.send('XXXXXX')
        time.sleep(1)
        shell.recv(1000)
        break
