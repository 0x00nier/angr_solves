import angr
import claripy

proj = angr.Project("./sample", main_opts = {"base _addr": 0})

password_chars = [claripy.BVS("flag %d" % i, 8) for i in range(32)]
password_ast = claripy.Concat(*password_chars)
state = proj.factory.entry_state(stdin=password_ast)
sim_mgr = proj.factory.simulation_manager(state)
sim_mgr.explore(find=0x1243, avoid=[0x1259])

if(len(sim_mgr.found) > 0):
	print("Solution found")
	found = sim_mgr.found[0]
	found_password = found.solver.eval(password_ast, cast_to=bytes)
	print("%" % found_password)
else:
	print("No solution found")
