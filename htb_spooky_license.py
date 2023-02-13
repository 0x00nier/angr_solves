import angr
import claripy
import sys

path_to_binary = "D:/Cybersecurity Stuff/HackingUnixBinariesStuff/Misc/spookylicence"
proj = angr.Project(path_to_binary, load_options={'auto_load_libs':False})

# Define the entry state with the input argument
argv = [proj.filename]
sym_arg_size = 32
sym_arg=claripy.BVS('sym_arg', 8*sym_arg_size)
argv.append(sym_arg)

entry_state = proj.factory.entry_state(args=argv,add_options={angr.sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS,angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY})

# Define a path group to perform the analysis
sim = proj.factory.simulation_manager(entry_state)

# Define the exit point for the `License Correct` message
exit_point = 0x400000+0x187d

# Define the exit point for the `License Invalid` message
avoid_point = 0x400000+0x1890

# Perform the analysis
sim.explore(find=exit_point, avoid=avoid_point,timeout=999999999)

# Check if there is a solution
if sim.found:
    print("Found a solution")
    solution = sim.found[0].solver.eval(argv[1], cast_to=bytes)
    print(solution)
else:
    print("No solution found")
