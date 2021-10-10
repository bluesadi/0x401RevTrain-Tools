import angr
from angr.state_plugins.inspect import BP_BEFORE

def hook(state):
    print(state.inspect.statement)
    print(state.scratch.irsb.statements[state.inspect.statement])
    #print(list(state.scratch.irsb.statements[state.inspect.statement].expressions))

proj = angr.Project('TestProgram')
proj.hook(addr=0x400794, hook=hook, length=5)
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
while len(simgr.active):
    for active in simgr.active:
        if b'Congratulations~' in active.posix.dumps(1):
            print(active.posix.dumps(0))
    simgr.step()