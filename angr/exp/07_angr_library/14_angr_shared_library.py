import angr
import claripy

proj = angr.Project('../dist/lib14_angr_shared_library.so', load_options={
    'main_opts' : {
        'base_addr' : 0x400000
    }
})
validate_addr = 0x4006D7
password = claripy.BVS('password', 8 * 8)
length = claripy.BVV(8, 32)
state = proj.factory.call_state(validate_addr, password, length)
simgr = proj.factory.simgr(state)
simgr.explore(find=0x400783)
found = simgr.found[0]
found.solver.add(found.regs.eax == 1)
print(found.solver.eval(password, cast_to=bytes))