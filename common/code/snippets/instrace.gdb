# On gdb: display/i $pc

set $i=0
break main
run
while ($i<100000)
si
set $i = $i + 1
end
quit
