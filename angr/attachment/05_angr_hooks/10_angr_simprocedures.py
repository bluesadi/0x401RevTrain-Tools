import angr
import claripy

class MyCheckEquals(angr.SimProcedure):

    def run(self, buffer_addr, length):
        buffer = self.state.memory.load(buffer_addr, length)
        return claripy.If(buffer == b'ORSDDWXHZURJRBDH', claripy.BVV(1, 32), claripy.BVV(0, 32))

proj = angr.Project('../dist/10_angr_simprocedures')
proj.hook_symbol(symbol_name='check_equals_ORSDDWXHZURJRBDH', simproc=MyCheckEquals())
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(
    find=lambda state : b'Good Job.' in state.posix.dumps(1),
    avoid=lambda state: b'Try again.' in state.posix.dumps(1)
)
print(simgr.found[0].posix.dumps(0))