"""

Detects opaque predicates in single basic blocks, see: http://zubcic.re/blog/experimenting-with-z3-proving-opaque-predicates and https://github.com/JonathanSalwan/Triton/blob/master/src/examples/python/proving_opaque_predicates.py

Sample output:

(angr)sam@angr-dev:~/code/opaque_predicates$ python test.py 
WARNING | 2016-08-20 21:13:33,412 | angr.path_group | No completion state defined for path group; stepping until all paths deadend
0x0:	xor	eax, eax
0x2:	jo	9
opaque predicate
WARNING | 2016-08-20 21:13:34,975 | angr.path_group | No completion state defined for path group; stepping until all paths deadend
0x0:	xor	eax, eax
0x2:	je	9
opaque predicate
WARNING | 2016-08-20 21:13:36,648 | angr.path_group | No completion state defined for path group; stepping until all paths deadend
0x0:	xor	eax, ebx
0x2:	je	9
not an opaque predicate
WARNING | 2016-08-20 21:13:37,933 | angr.path_group | No completion state defined for path group; stepping until all paths deadend
0x0:	and	eax, 0x3fffffff
0x5:	and	ebx, 0x3fffffff
0xb:	xor	ecx, edx
0xd:	xor	edx, edi
0xf:	add	eax, ebx
0x11:	jo	0x27
opaque predicate
WARNING | 2016-08-20 21:13:39,450 | angr.path_group | No completion state defined for path group; stepping until all paths deadend
0x0:	and	eax, 0x3fffffff
0x5:	and	ebx, 0x3fffffff
0xb:	xor	ecx, edx
0xd:	xor	edx, edi
0xf:	xor	eax, ebx
0x11:	je	0x27
not an opaque predicate
"""

import angr

traces = ["\x31\xC0\x0F\x80\x01\x00\x00\x00","\x31\xC0\x0F\x84\x01\x00\x00\x00", "\x31\xD8\x0F\x84\x01\x00\x00\x00", "\x25\xff\xff\xff\x3f\x81\xe3\xff\xff\xff\x3f\x31\xd1\x31\xfa\x01\xd8\x0f\x80\x10\x00\x00\x00", "\x25\xff\xff\xff\x3f\x81\xe3\xff\xff\xff\x3f\x31\xd1\x31\xfa\x31\xD8\x0F\x84\x10\x00\x00\x00"]


def test_for_opaque_predicate(trace):
    p = angr.Project('/bin/true') #Because we need a valid binary? :/
    s = p.factory.blank_state(addr=0x0)
    s.mem[0:].byte = trace
    pg = p.factory.path_group(s)    
    out =  pg.run()
    p.factory.block(0).capstone.pp()
    if len(out.errored) == 1:
        return True #Only one path - must be an opaque predicate
    sat_paths = 0     
    for i in out.errored:
        if i.state.satisfiable():
            sat_paths +=1
    if sat_paths > 1:
        return False #multiple valid paths, jmp must be optional
    return True #Only one achievable path

if __name__ == "__main__":
    for t in traces:
        if test_for_opaque_predicate(t):
            print "opaque predicate"
        else:
            print "not an opaque predicate" 