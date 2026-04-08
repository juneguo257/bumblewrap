import time
import os
import sys

time.sleep(1)
os.execvp(sys.argv[1], sys.argv[1:])