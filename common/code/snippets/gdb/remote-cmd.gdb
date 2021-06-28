# Given remote terminal running `gdbserver :2345 ./remote_executable`, we connect to that server.
# target extended-remote localhost:2345
target extended-remote 192.168.1.4:2345

# Load our custom gdb command `rcmd`.
source ./remote-cmd.py

# Run until a point where libc has been loaded, e.g. start of main().
b main
r

# Don't need the main() breakpoint anymore.
del 1

# Run the remote command, e.g. `ls`.
rcmd ls
