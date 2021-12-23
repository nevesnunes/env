#!/usr/bin/env python3

import angr
import monkeyhex
from angr import sim_options as so


def main():
    # Run Initialization
    p = angr.Project('./test',auto_load_libs=False)
    extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY}
    es = p.factory.entry_state(add_options=extras)
    sm = p.factory.simulation_manager(es, save_unconstrained=True)

    # Set Target Address
    mainAddr = 0x8048464
    EndAddr = 0x080485E8

    # Run to mainAddr
    sm.explore(find=mainAddr)
    es = sm.found[0]

    EndAddr = es.solver.BVV(EndAddr,32)
    maybe = es.regs.eip == EndAddr
    sm = p.factory.simulation_manager(es, save_unconstrained=True)
    num = 0

    while es.solver.is_false(maybe):
        block = p.factory.block(es.solver.eval(es.regs.eip))
        # print(block.pp())
        print(block.vex)
        sm.step()
        sm.active
        es = sm.active[0]
        maybe = es.regs.eip == EndAddr
        num = num + 1
        '''
        with open('log.txt', 'a') as f:
            f.writelines(block.vex)'''

    block = p.factory.block(es.solver.eval(es.regs.eip))
    # print(block.pp())
    print(block.vex)
    '''
    with open('log.txt', 'a') as f:
        f.writelines(block.vex)

    print("All Show!")
    print(num)'''


main()
————————————————
版权声明：本文为CSDN博主「ZERO - A - ONE」的原创文章，遵循CC 4.0 BY - SA版权协议，转载请附上原文出处链接及本声明。
原文链接：https: // blog.csdn.net / kelxLZ / article / details / 120270212
