import angr
import claripy

proj = angr.Project('../dist/05_angr_symbolic_memory')
state = proj.factory.blank_state(addr=0x80485FE)
password0 = claripy.BVS('password0', 64)
password1 = claripy.BVS('password1', 64)
password2 = claripy.BVS('password2', 64)
password3 = claripy.BVS('password3', 64)
state.mem[0xA1BA1C0].uint64_t = password0
state.mem[0xA1BA1C0 + 8].uint64_t = password1
state.mem[0xA1BA1C0 + 16].uint64_t = password2
state.mem[0xA1BA1C0 + 24].uint64_t = password3
simgr = proj.factory.simgr(state)
simgr.explore(find=0x804866A)
solver = simgr.found[0].solver
print(f'password0: {solver.eval(password0, cast_to=bytes)}')
print(f'password1: {solver.eval(password1, cast_to=bytes)}')
print(f'password2: {solver.eval(password2, cast_to=bytes)}')
print(f'password3: {solver.eval(password3, cast_to=bytes)}')