import angr
import claripy

proj = angr.Project('../dist/07_angr_symbolic_file')
state = proj.factory.blank_state(addr=0x80488D3)
password0 = claripy.BVS('password0', 64)
sim_file = angr.SimFile(name='OJKSQYDP.txt', content=password0, size=0x40)
state.fs.insert('OJKSQYDP.txt', sim_file)
simgr = proj.factory.simgr(state)
simgr.explore(find=0x80489AD)
solver = simgr.found[0].solver
print(f'password0: {solver.eval(password0, cast_to=bytes)}')