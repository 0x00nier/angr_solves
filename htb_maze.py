import angr
import claripy


def main():
    # Define the base address and addresses to find and avoid
    BASE_ADDR = 0x0
    FIND_ADDR = BASE_ADDR + 0x124f
    AVOID_ADDR = BASE_ADDR + 0x1267

    # Create an Angr project
    proj = angr.Project("./dec_maze", main_opts = {"base_addr": 0})

    # Define the start address and length of input buffer
    START_ADDR = BASE_ADDR + 0x1169

    flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(38)]
    input_buf = claripy.Concat(*flag_chars)

    # Define state with symbolic input
    state = proj.factory.entry_state(addr=START_ADDR, stdin=input_buf, add_options=angr.options.unicorn)

    for k in flag_chars:
        state.solver.add(k != 0)
        state.solver.add(k != 10)

    # Simulate until either the find or avoid address is reached
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

    # Check if a solution is found
    if simgr.found:
        found_state = simgr.found[0]
        # Get the concrete value of the symbolic input buffer
        solution = found_state.solver.eval(input_buf, cast_to=bytes)
        print("Solution found:", solution)
    else:
        print("Solution not found.")

if __name__ == "__main__":
    main()
