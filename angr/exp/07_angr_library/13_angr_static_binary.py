import angr

proj = angr.Project('../dist/13_angr_static_binary')

proj.hook_symbol('printf', angr.SIM_PROCEDURES['libc']['printf']())
proj.hook_symbol('__isoc99_scanf',angr.SIM_PROCEDURES['libc']['scanf']())
proj.hook_symbol('strcmp', angr.SIM_PROCEDURES['libc']['strcmp']())
proj.hook_symbol('puts', angr.SIM_PROCEDURES['libc']['puts']())
proj.hook_symbol('__libc_start_main',angr.SIM_PROCEDURES['glibc']['__libc_start_main']())
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(
    find=lambda state : b'Good Job.' in state.posix.dumps(1),
    avoid=lambda state: b'Try again.' in state.posix.dumps(1)
)
print(simgr.found[0].posix.dumps(0))