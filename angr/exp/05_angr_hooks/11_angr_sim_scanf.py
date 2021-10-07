import angr

proj = angr.Project('../dist/11_angr_sim_scanf')
proj.hook_symbol("__isoc99_scanf", angr.SIM_PROCEDURES['libc']['scanf']())  # 多此一举
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(
    find=lambda state : b'Good Job.' in state.posix.dumps(1),
    avoid=lambda state: b'Try again.' in state.posix.dumps(1)
)
print(simgr.found[0].posix.dumps(0))