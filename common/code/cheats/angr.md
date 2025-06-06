# docs

- [GitHub \- lcatro/Angr\-CTF\-Learn\-Note: The learn note of Angr\-CTF \.\.](https://github.com/lcatro/Angr-CTF-Learn-Note)
- [GitHub \- jakespringer/angr\_ctf](https://github.com/jakespringer/angr_ctf)
- [GitHub \- andreafioraldi/angrgdb: Use angr inside GDB\. Create an angr state from the current debugger state\.](https://github.com/andreafioraldi/angrgdb)
- [Material :: flagbot](https://flagbot.ch/material/#lesson-5-constraint-solving-and-symbolic-execution-13-april-2020)
- [angr\-doc/CHEATSHEET\.md at master · angr/angr\-doc · GitHub](https://github.com/angr/angr-doc/blob/master/CHEATSHEET.md)
- [angr for real\-world use cases \| volodya](https://plowsec.github.io/angr-introspection-2024.html)

# init state

- if: requires shared library constructors or preinitializers (e.g. `scanf()`)
    - then: `full_init_state()`
    - https://docs.angr.io/core-concepts/states#state-presets
- if: process dump
    - then: `load_shellcode()` || `Project("./coredump")`
    - [Loading memory during symbolic execution · Issue \#1969 · angr/angr · GitHub](https://github.com/angr/angr/issues/1969)

# constraints

```python
import claripy

def AND1(c):
    '''constrain 1: printable'''
    return claripy.And(33 <= c , c <= 126)

length = 29
flag = claripy.BVS('flag', length*8)
for i in range(length):
    state.solver.add( AND1(flag.get_byte(i)) ) 
```

- https://blog.efiens.com/tamuctf-2019/
- https://github.com/acdwas/ctf/blob/master/2020/Google_2020/rev/beginner/solver.py

# hooks

```python
def crc32_hook(state):
  pass

instruction_len = 5
project.hook(0x4012a2, crc32_hook, length=instruction_len)
```

- https://docs.angr.io/extending-angr/simprocedures
    > The general rule is, if you want your SimProcedure to either be able to extract function arguments or cause a program return, write a full SimProcedure class. Otherwise, use a user hook.

# argv

```python
proj = angr.Project('./a.out', main_opts={'base_addr': 0}, auto_load_libs=False)
arg = claripy.BVS('arg', 8*0x20)
state = proj.factory.entry_state(args=['./a.out', arg])
```

# stdin

```python
simfile = angr.SimFile('/dev/stdin',size=symsize)
# ||
simfile = angr.SimFile('/tmp/stdin',size=symsize)

state = p.factory.entry_state(stdin=simfile)
```

- [justCTF 2019 - FSMir](https://ctftime.org/writeup/17632)
- https://docs.angr.io/advanced-topics/file_system

# memory read / store

```python
in_array_addr = proj.loader.find_symbol('in_array').rebased_addr
in_array_size = 16 * 1
initial_state = proj.factory.entry_state(addr=main)
for i in range(in_array_size):
    ch = initial_state.solver.BVS('ch{}'.format(i), 8)
    initial_state.solver.add(ch >= 0)
    initial_state.solver.add(ch < 17)
    initial_state.memory.store(in_array_addr+i, ch)

my_buf = 0x12345678
state.memory.store(addr=my_buf, data=flag)
state.regs.rdi = my_buf

flag_data = goal_state.memory.load(in_array_addr, in_array_size)
```

- https://reverseengineering.stackexchange.com/questions/21565/angr-populate-int-array-with-constraints
- https://docs.angr.io/core-concepts/states

# [!] endianess

```python
addr = state.regs.esi
b32 = state.memory.load(addr).reversed
```

- [UIUCTF 2020 / Tasks / cricket32 / Writeup](https://ctftime.org/writeup/22420)
    - https://ohaithe.re/post/624142953693249536/uiuctf-2020-cricket32

# multi-threading

```python
p = angr.Project('./angrybird2')
init = p.factory.blank_state(addr=main)
pg = p.factory.path_group(init, threads=8)
ex = pg.explore(find=find, avoid=avoid)
```

# debug

- input api changes
    - [I wonder how to give program input stdin \(scanf,ReadConsoleA,read function\) by angr · Issue \#1566 · angr/angr · GitHub](https://github.com/angr/angr/issues/1566)
- increase claripy.BVS number of bits for scanf
    - https://reverseengineering.stackexchange.com/questions/19164/problem-with-scanf-fgets-in-angr-stdin-exploration

```python
import signal
def killmyself():
    os.system('kill %d' % os.getpid())
def sigint_handler(signum, frame):
    print 'Stopping Execution for Debug. If you want to kill the programm issue: killmyself()'
    if not "IPython" in sys.modules:
        import IPython
        IPython.embed()

signal.signal(signal.SIGINT, sigint_handler)

@p.hook(0x00400ca9)
def debug_func(state):
    rdi_value = state.regs.rdi
    print ( 'rdi is point to {}'.format(rdi_value) )

result = simgr.found[0]
for i in range(3):
    print (result.posix.dumps(i))
print (result.solver.eval(flag, cast_to=bytes))
```

```
sm.errored[0]
pp vars(ex.unsat[0])

WARNING | 2020-07-17 17:16:50,623 | angr.state_plugins.symbolic_memory | Filling register rbp with 8 unconstrained bytes referenced from 0x40071a (main+0x0 in elementary (0x71a))
WARNING | 2020-07-17 17:16:52,567 | angr.state_plugins.symbolic_memory | Filling register rbx with 8 unconstrained bytes referenced from 0x4007b6 (function0+0x4 in elementary (0x7b6))
<SimulationManager with 1 found, 713 avoid>
flag: p4{I_really_hope_you_automated_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}????????????????????????
~/code/snippets/angr/solve_with_avoids.py elementary addresses_to_avoid  375.71s user 34.03s system 125% cpu 5:27.16 total
```

- [Got an unsat result · Issue \#1360 · angr/angr · GitHub](https://github.com/angr/angr/issues/1360)

# install

```bash
. ~/share/venv/angr/bin/activate
pip3 install angr
pip3 install -U protobuf
```

- https://docs.angr.io/introductory-errata/install
- https://pypi.org/project/angr/#history

# alternatives

- https://blog.quarkslab.com/triton-under-the-hood.html
- https://github.com/trailofbits/manticore/wiki

# case studies

- http://ctfhacker.com/reverse/2018/09/16/flareon-2018-level6-angr.html
- https://binaryresearch.github.io/2020/01/22/more-angr-defeating-5-ELF-crackmes.html
- https://jkrshnmenon.wordpress.com/2019/01/31/even-the-king-bows-before-angr/
    - ~/code/snippets/angr/king.py
- [CTFtime\.org / SwampCTF 2018 / Journey / Writeup](https://ctftime.org/writeup/9452)
