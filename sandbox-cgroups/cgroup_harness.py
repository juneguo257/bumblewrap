import time
import os
import sys

# NOTE: write pipe is argument 1, read pipe is argument 2, program to run and arguments to use for the program are arguments 3+

with os.fdopen(int(sys.argv[1]), 'w') as write_pipe:
    write_pipe.write(f"{os.getpid()}")

with os.fdopen(int(sys.argv[2]), 'r') as read_pipe:
    read_pipe.read()

# start process
starting_arg = 3

harness_two = os.path.dirname(os.path.abspath(__file__)) + "/cgroup_harness2.py"

os.execvp("python3", ["python3", harness_two] + sys.argv[starting_arg:])