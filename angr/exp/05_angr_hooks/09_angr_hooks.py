import angr
import claripy

proj = angr.Project('../dist/09_angr_hooks')

@proj.hook(addr=0x80486B3, length=5)  # check_equals_XYMKBKUHNIQYNQXE
def my_check_equals(state):
    buffer_addr = 0x804A054
    buffer = state.memory.load(buffer_addr, 16)
    state.regs.eax = claripy.If(buffer == b'XYMKBKUHNIQYNQXE', claripy.BVV(1, 32), claripy.BVV(0, 32))

state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(
    find=lambda state : b'Good Job.' in state.posix.dumps(1),
    avoid=lambda state: b'Try again.' in state.posix.dumps(1)
)
print(simgr.found[0].posix.dumps(0))