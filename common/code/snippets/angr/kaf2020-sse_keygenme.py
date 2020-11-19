#!/usr/bin/env python3

import angr
import sys
import claripy

FLAG_LEN = 23  # Input length without the newline
STDIN_FD = 0
base_addr = 0x100000  # Base address found with Ghidra
our_binary = "./SSE_KEYGENME"

# Initialize a project with our binary and base address
proj = angr.Project(our_binary, main_opts={"base_addr": base_addr})

# Generate our input with <FLAG_LEN> BVS et ONE BVV for the new line
flag_chars = [claripy.BVS("flag_%d" % i, 8) for i in range(FLAG_LEN)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b"\n")])

# Initialize a state with our binary, dynamic input and unicorn
state = proj.factory.full_init_state(
    args=[our_binary], add_options=angr.options.unicorn, stdin=flag,
)

# Add contraints to the dynamic input using only printable characters
for k in flag_chars:
    state.solver.add(k >= ord("!"))
    state.solver.add(k <= ord("~"))

# Create a simulation manager with our state
simgr = proj.factory.simulation_manager(state)


# Note : I tried to use addresses of sucess and failure but it wasn't working, so i came up with this functions parsing the screen output
# Success function
def is_successful(state):
    output = state.posix.dumps(sys.stdout.fileno())
    if b"Success" in output:
        return True
    return False


# Failure function
def is_ko(state):
    output = state.posix.dumps(sys.stdout.fileno())
    if b"Wrong" in output:
        return True
    return False


# Start exploration using our guidance
simgr.explore(find=is_successful, avoid=is_ko)

# Display the flag
if len(simgr.found) > 0:
    for found in simgr.found:
        print(found.posix.dumps(STDIN_FD).decode())
