import time
import os
import sys

time.sleep(0.5)
os.execvp(sys.argv[1], sys.argv[1:])