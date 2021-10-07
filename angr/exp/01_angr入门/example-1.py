import claripy
import angr

proj = angr.Project('example-1')
sym_flag = claripy.BVS('flag', 100 * 8)
state = proj.factory.entry_state(stdin=sym_flag)
simgr = proj.factory.simgr(state)
simgr.explore(find=0x40138D)
solver = simgr.found[0].solver
solver.add(simgr.found[0].regs.eax == 0)
print(solver.eval(sym_flag, cast_to=bytes))