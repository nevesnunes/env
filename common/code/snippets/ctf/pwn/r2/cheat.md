https://radare.gitbooks.io/radare2book/content/refcard/intro.html

# List functions
afl

# Graph
ag > b.dot

# Disassemble function:
s main
pdf

pdf@main
pdr@main

# Print call graph:
agc > /tmp/foo.dot xdot /tmp/foo.dot

# Print a detailed graph:
ag $$ > /tmp/c2.dot

# Disassemble instruction:
pD 2

# Seek to a specific memory location:
s 0x08048470

# Write hex value:
wx eb

# Debugging/Visual Mode
r2 -d ./file

# Set breakpoint
db 0x00401383

# Remove breakpoint
db -0x00401383

# List breakpoints
db 0x00401383 - 0x004013841 --x sw break enabled cmd="" name="0x00401383"

# Continue
dc

# Switch to Visual Mode
V

# Cycle through Visual modes
p

# Step through code
s

# Switch to graph view (in Visual Mode)
V

# Pattern generation
ragg2 -p 300 -r

# Get assembly instruction
rasm2 -a x86 -b 32 'jmp 16'
