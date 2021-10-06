import angr

angr.exploration_techniques.Veritesting
proj = angr.Project('../dist/12_angr_veritesting')
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.use_technique(angr.exploration_techniques.Veritesting())
simgr.explore(
    find=lambda state : b'Good Job.' in state.posix.dumps(1),
    avoid=lambda state: b'Try again.' in state.posix.dumps(1)
)
print(simgr.found[0].posix.dumps(0))