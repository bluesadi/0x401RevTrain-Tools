import angr
import claripy

proj = angr.Project('../dist/04_angr_symbolic_stack')
state = proj.factory.blank_state(addr=0x8048694)
state.regs.ebp = state.regs.esp + 40
state.regs.esp = state.regs.ebp - 0xC + 4
password0 = claripy.BVS('password0', 32)
password1 = claripy.BVS('password1', 32)
state.stack_push(password0)
state.stack_push(password1)
state.regs.esp = state.regs.ebp - 40
simgr = proj.factory.simgr(state)
simgr.explore(find=0x80486E1)
solver = simgr.found[0].solver
print(f'password0: {hex(solver.eval(password0))}')
print(f'password1: {hex(solver.eval(password1))}')
