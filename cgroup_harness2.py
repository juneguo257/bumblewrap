import time
import os
import sys


os.close(int(sys.argv[1]))

starting_arg = 2

os.execvp(sys.argv[starting_arg], sys.argv[starting_arg:])