import angr

proj = angr.Project('TestProgram_fla')
block = proj.factory.block(0x4008A8)
block.vex.pp()