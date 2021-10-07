import angr

def is_successful(state):
    return b'Good Job.' in state.posix.dumps(1)

def should_avoid(state):
    return b'Try again.' in state.posix.dumps(1)

proj = angr.Project('../dist/02_angr_find_condition')
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
# simgr.explore(find=is_successful, avoid=should_avoid)
simgr.explore(
    find=lambda state : b'Good Job.' in state.posix.dumps(1),
    avoid=lambda state: b'Try again.' in state.posix.dumps(1)
)
print(simgr.found[0].posix.dumps(0))