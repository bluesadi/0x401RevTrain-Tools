import angr

proj = angr.Project('dist/01_angr_avoid')
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(find=0x80485E0, avoid=0x80485A8)
print(simgr.found[0].posix.dumps(0))