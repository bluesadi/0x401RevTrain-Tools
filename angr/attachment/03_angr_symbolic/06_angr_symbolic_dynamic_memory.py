import angr
import claripy

proj = angr.Project('../dist/06_angr_symbolic_dynamic_memory')
state = proj.factory.blank_state(addr=0x8048696)
password0 = claripy.BVS('password0', 64)
password1 = claripy.BVS('password1', 64)
state.mem[0xABCC700].uint64_t = password0
state.mem[0xABCC700 + 8].uint64_t = password1
state.mem[0xABCC8A4].uint32_t = 0xABCC700
state.mem[0xABCC8AC].uint32_t = 0xABCC700 + 8
simgr = proj.factory.simgr(state)
simgr.explore(find=0x8048759)
solver = simgr.found[0].solver
print(f'password0: {solver.eval(password0, cast_to=bytes)}')
print(f'password1: {solver.eval(password1, cast_to=bytes)}')