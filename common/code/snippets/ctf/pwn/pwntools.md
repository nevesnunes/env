# Pwntools Quick Reference Guide

> pwntools is a CTF framework and exploit development library. Written in Python, it is designed for rapid prototyping and development, and intended to make exploit writing as simple as possible.

## Context

Setting the Target Architecture and OS:

```python
context(arch='arm', os='linux', endian='big', log_level='debug')
```

## Log

It’s similar to `logging.Logger`.

```python
>>> log.info('Hello, world!')
[*] Hello, world!
```

## Making connections

### New a tube

Create a tube instance from a local program or a remote conncetion.

```python
conn = process('./pwn')
conn = remote('ftp.debian.org',21)
```

### Comunication

#### Send and recv

There are many functions to send or recv data via tube.

```python
recv(numb = 4096, timeout = default)
recvuntil(delims, drop=False, timeout = default)
recvn(numb, timeout = default)
recvlines(numlines, keepends = False, timeout = default)
recvline(keepends = True, timeout = default)
recvregex(regex, exact = False, timeout = default)
recvrepeat(timeout = default)  # Receives data until a timeout or EOF is reached.
recvall(self, timeout=Timeout.forever)  # Receives data until EOF is reached.
...
send(data)
sendline(line)
...
interactive()
```

#### Listen

```python
l = listen(port=2333, bindaddr = "0.0.0.0")
c = l.wait_for_connection()
c.recv()
```

## ELF Manipulation

Stop hard-coding things\! Look them up at runtime with `pwnlib.elf`.

```python
>>> e = ELF('/bin/cat')
>>> print hex(e.address)
0x400000
>>> print hex(e.symbols['write'])
0x401680
>>> print hex(e.got['write'])
0x60b070
>>> print hex(e.plt['write'])
0x401680
>>> e.address = 0x0
>>> print hex(e.symbols['write'])
0x1680
```

You can even patch and save the files.

```python
>>> e = ELF('/bin/cat')
>>> e.read(e.address+1, 3)
'ELF'
>>> e.asm(e.address, 'ret')
>>> e.save('/tmp/quiet-cat')
>>> disasm(file('/tmp/quiet-cat','rb').read(1))
```

## Debug with gdb

`pwnlib.gdb.attach()` starts GDB in a **new terminal** and attach to target.

Target can be a process, (addr, port), or ssh channel.

```python
p = process('./helloworld')
gdb.attach(p, execute="b *0x4000000")  # execute:GDB script to run after attaching.
gdb.attach(('127.0.0.1', 8765))  # attach to remote gdb server
s = ssh(host='rpi', user='pi')
conn = s.process('/tmp/helloworld')
gdb.attach(conn)  # start gdb on remote server via ssh
```

If you want to start GDB in a split window in tmux:

```python
context.terminal = ['tmux', 'splitw', '-h']
context.terminal = ['tmux', 'splitw', '-v']
```

## Fmtstr

`pwnlib.fmtstr.fmtstr_payload(offset, writes, numbwritten=0, write_size='byte')`

It can generate payload for 32 or 64 bits architectures. The size of the addr is taken from `context.bits`

Parameters:

  - offset (int) – the first formatter’s offset you control
  - writes (dict) – dict with addr, value {addr: value, addr2: value2}
  - numbwritten (int) – number of byte already written by the printf function
  - write\_size (str) – must be byte, short or int. Tells if you want to write byte by byte, short by short or int by int (hhn, hn or n)

## DynELF

`pwnlib.dynelf` — Resolving remote functions using leaks

Resolve symbols in loaded, dynamically-linked ELF binaries. Given a function which can leak data at an arbitrary address, any symbol in any loaded library can be resolved.

This is an example in the document:

```python
# Assume a process or remote connection
p = process('./pwnme')
# Declare a function that takes a single address, and
# leaks at least one byte at that address.
def leak(address):
    data = p.read(address, 4)
    log.debug("%#x => %s" % (address, (data or '').encode('hex')))
    return data
# For the sake of this example, let's say that we
# have any of these pointers.  One is a pointer into
# the target binary, the other two are pointers into libc
main   = 0xfeedf4ce
libc   = 0xdeadb000
system = 0xdeadbeef
# With our leaker, and a pointer into our target binary,
# we can resolve the address of anything.
#
# We do not actually need to have a copy of the target
# binary for this to work.
d = DynELF(leak, main)
assert d.lookup(None,     'libc') == libc
assert d.lookup('system', 'libc') == system
# However, if we *do* have a copy of the target binary,
# we can speed up some of the steps.
d = DynELF(leak, main, elf=ELF('./pwnme'))
assert d.lookup(None,     'libc') == libc
assert d.lookup('system', 'libc') == system
# Alternately, we can resolve symbols inside another library,
# given a pointer into it.
d = DynELF(leak, libc + 0x1234)
assert d.lookup('system') == system
```

## Utility

### Generation of unique sequences

`pwnlib.util.cyclic.cyclic(length = None, alphabet = string.ascii_lowercase, n = 4)`

`pwnlib.util.cyclic.cyclic_find(subseq, alphabet = string.ascii_lowercase, n = None)`

```python
>>> cyclic(20)
'aaaabaaacaaadaaaeaaa'
>>> cyclic(alphabet = "ABC", n = 3)
'AAABAACABBABCACBACCBBBCBCCC'
>>> cyclic_find(cyclic(alphabet = "ABC", n = 3)[3:6], alphabet = "ABC", n = 3)
3
```

### Assembly and Disassembly

```python
>>> asm('mov eax, 0').encode('hex')
'b800000000'
>>> print disasm('6a0258cd80ebf9'.decode('hex'))
   0:   6a 02                   push   0x2
   2:   58                      pop    eax
   3:   cd 80                   int    0x80
   5:   eb f9                   jmp    0x0
```

### Packing Integers

`p8()`, `p16()`, `p32()`, `p64()`, `u8()`, `u16()`, `u32()`, `u64()`

```python
>>> import struct
>>> p32(0xdeadbeef) == struct.pack('I', 0xdeadbeef)
True
>>> leet = '37130000'.decode('hex')
>>> u32('abcd') == struct.unpack('I', 'abcd')[0]
True
```

`pwnlib.util.packing.pack/unpack(number, word_size = None, endianness = None, sign = None, **kwargs)`
