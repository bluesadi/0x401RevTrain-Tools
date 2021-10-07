import angr

def check_puts(state):
    puts_parameter = state.memory.load(state.regs.esp + 4, 4, endness=proj.arch.memory_endness)
    if state.solver.symbolic(puts_parameter):
        good_job_string_address = 0x484F6038
        is_vulnerable_expression = puts_parameter == good_job_string_address
        copied_state = state.copy()
        copied_state.add_constraints(is_vulnerable_expression)
        if copied_state.satisfiable():
            state.add_constraints(is_vulnerable_expression)
            return True
    return False

def is_successful(state):
    puts_address = 0x08048370
    if state.addr == puts_address:
        return check_puts(state)
    return False

proj = angr.Project('../dist/15_angr_arbitrary_read')
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(find=is_successful)
print(simgr.found[0].posix.dumps(0))