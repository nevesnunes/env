#!/usr/bin/env python3

import angr
from angr.exploration_techniques.dfs import DFS
 
GOAL = 0x400B58
XOR_FUNC = 0x400AB9
RUN_TEST = 0x400A16
DECRYPT_FUNC = 0x401793
 
inputs = {}
LE = angr.archinfo.Endness.LE
 
 
class scanf_hook(angr.SimProcedure):
    def run(self):
        global inputs
        if self.state.solver.eval(self.state.regs.rdi) == 0x4041F9:
            # %s
            return
        elif self.state.solver.eval(self.state.regs.rdi) == 0x40394F:
            # %d
            expr = self.state.solver.BVS('inp', 32)
            self.state.solver.add(expr > 0)
            self.state.solver.add(expr < 5)
            block_addr = list(self.state.history.bbl_addrs)[-3]
            inputs[block_addr] = expr
            self.state.memory.store(self.state.regs.rsi, expr, endness=LE)
        else:
            print("!!!!!!!!!!!!!New condition!!!!!!!!!!!!!!")
            print(self.state.solver.eval(self.state.regs.rdi))
 
def get_target(cfg):
    targets = []
    for addr in cfg.kb.callgraph.predecessors(GOAL):
        sites = []
        func = cfg.functions.function(addr)
        for x in func.get_call_sites():
            if func.get_call_target(x) == GOAL:
                b = cfg.get_any_node(x).block
                ins = b.capstone.insns[-3]
                op = ins.insn.operands[1]
                if op.imm == 1:
                    targets.append(x)
    return targets
 
 
def apply_constraints(state):
    global inputs
    # This is the address which get_target returns
    if state.addr != 0x400C3C:
        return False
    stats = [0x60716C, 0x607170, 0x607174, 0x607178, 0x60717C]
    for addr in stats:
        expr = state.memory.load(addr, 4, endness=LE)
        state.solver.add(expr == 5)
 
    return state.satisfiable()
 
 
def explore():
    p = angr.Project('./Patched.bin', load_options={'auto_load_libs': False})
    # cfg = p.analyses.CFG()
    # target = get_target(cfg)
 
    p.hook_symbol('__isoc99_scanf', scanf_hook())
    p.hook(XOR_FUNC, angr.SIM_PROCEDURES['stubs']['Nop']())
    p.hook(RUN_TEST, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    p.hook(DECRYPT_FUNC, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
 
    # This one takes nearly 2 hours to find a path
    # s = p.factory.blank_state(addr=0x403780)
 
    # And this one takes 40 minutes
    s = p.factory.blank_state(addr=0x403197)
    pg = p.factory.simulation_manager(s, auto_drop=['avoid', 'unsat'])
    pg.use_technique(DFS())
    pg.explore(find=apply_constraints, avoid=GOAL)
 
    for state in pg.found:
        print("Inputs")
        for x in list(state.history.bbl_addrs):
            if x in inputs.keys():
                print(state.solver.eval(inputs[x]))
 
 
