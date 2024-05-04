import platform
from pwn import log,context

def setup(debug:bool=False):
    sys = platform.uname()
    if "amd" in sys.release:
        context.arch = "amd64"
    elif "i386" in sys.release:
        context.arch = "i386"
    elif "arm" in sys.release:
        context.arch = "arm"
    if "64" in sys.machine:
        context.bits = 64
    elif "32" in sys.machine:
        context.bits
    if debug:
        context.log_level = "debug"
    