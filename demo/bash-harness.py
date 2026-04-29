import os

os.setuid(os.getuid())
os.execv("/usr/bin/bash", ["/usr/bin/bash"])