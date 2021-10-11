import angr
import claripy
import sys

proj = angr.Project('EasyVM')
flag = claripy.BVS('flag', 100 * 8)
state = proj.factory.entry_state(stdin=flag)
simgr = proj.factory.simgr(state)
while len(simgr.active):
    for active in simgr.active:
        print(active)
        if active.addr == 0x80492B2:
            print(active.solver.eval(flag, cast_to=bytes))
            sys.exit(0)
    simgr.step()