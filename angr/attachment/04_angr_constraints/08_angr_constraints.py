import angr
import claripy

proj = angr.Project('../dist/08_angr_constraints')
state = proj.factory.blank_state(addr=0x8048622)
password = claripy.BVS('password', 16 * 8)
buffer_addr = 0x804A050
state.memory.store(buffer_addr, password)
simgr = proj.factory.simgr(state)
simgr.explore(find=0x8048669)
found = simgr.found[0]
found.add_constraints(found.memory.load(buffer_addr, 16) == b'AUPDNNPROEZRJWKB')
print(found.solver.eval(password, cast_to=bytes))