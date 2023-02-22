import angr, claripy
import logging
from string import printable
logging.getLogger("angr").setLevel(logging.INFO)

p = angr.Project("./sample", main_opts = {"base _addr": 0}, load_options={'auto_load_libs':False})
USER_DATA_LEN=36

user_data=claripy.BVS("user_data",USER_DATA_LEN*8)
s = p.factory.entry_state(stdin=user_data)
for i in range(USER_DATA_LEN):
	s.solver.add(
		claripy.Or(*(
				user_data.get_byte(i) == x
				for x in printable
			))
		)

# Turn veritesting off before
sm = p.factory.simgr(veritesting=True)

# assumes symbols for functions are there
flag=p.loader.find_symbol("read_and_print_flag").rebased_addr
sm.exploire(find=flag, avoid=0x1032)

if sm.found:
	e=sm.found[0]
	print(e.posix.stdin.concretize())
else:
	print("lul")
