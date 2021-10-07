import angr

proj = angr.Project('../dist/00_angr_find')
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(find=0x8048678)
print(simgr.found[0].posix.dumps(0))