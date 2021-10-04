import angr
import claripy

proj = angr.Project('../dist/03_angr_symbolic_registers')
state = proj.factory.blank_state(addr=0x8048980)
password0 = claripy.BVS('password0', 32)
password1 = claripy.BVS('password1', 32)
password2 = claripy.BVS('password2', 32)
state.regs.eax = password0
state.regs.ebx = password1
state.regs.edx = password2
simgr = proj.factory.simgr(state)
simgr.explore(find=0x80489E6)
solver = simgr.found[0].solver
print(f'password0: {hex(solver.eval(password0))}')
print(f'password1: {hex(solver.eval(password1))}')
print(f'password2: {hex(solver.eval(password2))}')