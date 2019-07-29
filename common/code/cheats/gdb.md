# +

https://github.com/taskcluster/react-gdb

step through stack frame

compile a dummy file with -g that has the types you need and then symbol-file it into gdb to get access to the types. This of course has caveats, you have to use the correct compiler and library versions, correct compiler target and ABI-changing flags, etc.

info f
info args

# Functions

define callstack
     set $Cnt = $arg0

     while($Cnt)
        commands $Cnt
        silent
        bt
        c
        end
        set $Cnt = $Cnt - 1
     end
end

set pagination off
set logging file gdb.txt
set logging on

br fun_convert
commands
    bt
    print "Sample print command 1 \n"
    continue
end

continue

gdb -x FILE
gdb -ex run --args prog arg

checkpoint
i checkpoint
restart checkpoint-id
