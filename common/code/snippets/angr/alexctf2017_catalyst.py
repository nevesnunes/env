#!/usr/bin/env python3

import angr
import IPython
from ctypes import CDLL


def get_uname(p):
    s = p.factory.blank_state(addr=0x400cdd)
    uname = s.se.BVS('uname', 24*8)
    s.memory.store(0x6021e0, uname)
    s.regs.rdi = s.se.BVV(0x6021e0, 64)
    pg = p.factory.path_group(s)
    pg.explore(find=0x400d90, avoid=0x400d7c)
    for p in pg.found:
        state = p.state
        return state.se.any_str(uname)


def get_password(p, name):
    cfg = p.analyses.CFGAccurate()
    starts = []
    avoids = []
    rands = []
    f = cfg.functions.get(0x400977)
    call_sites = f.get_call_sites()
    for address, function in cfg.functions.iteritems():
        if function.name == 'rand':
            rand_func = function
            break
    for address, function in cfg.functions.iteritems():
        if function.name == 'puts':
            puts = function
            break
    for x in call_sites:
        target = f.get_call_target(x)
        if target == rand_func.addr:
            starts.append(x+10)
        elif target == puts.addr:
            avoids.append(x)
    starts.sort()
    avoids.sort()
    avoids.pop(0)
    starts.append(0x400c39)
    starts[0] = starts[0]-4

    libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
    seed = 0
    for x in range(0, len(name), 4):
        seed += int(name[x:x+4][::-1].encode('hex'), 16)
    libc.srand(seed & 0xffffffff)

    for x in range(10):
        rands.append(libc.rand())

    class rand(angr.simuvex.SimProcedure):
        def run(self):
            retval = self.state.procedure_data.global_variables['rand_val']
            return retval

    p.hook_symbol('rand', rand)
    final_str = ""

    for x in range(10):
        s = p.factory.blank_state(addr=starts[x])
        password = s.se.BVS('password', 32)
        s.regs.ebx = password
        s.procedure_data.global_variables['rand_val'] = rands[x]
        pg = p.factory.path_group(s)
        pg.explore(find=starts[x+1], avoid=avoids[x])
        for path in pg.found:
            state = path.state
            final_str += state.se.any_str(password)[::-1]
        return final_str


if __name__ == '__main__':
    filename = 'catalyst'
    p = angr.Project(filename, load_options={'auto_load_libs': False})
    uname = get_uname(p)
    passwd = get_password(p, uname)
    print "Username = {}".format(uname)
    print "Password = {}".format(passwd)
