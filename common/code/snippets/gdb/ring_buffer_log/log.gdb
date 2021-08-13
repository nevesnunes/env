define crash_log

set $data = crash_log->data
set $read = crash_log->read
set $write = crash_log->write
set $mask = crash_log->mask
while $read < $write
    printf "%c", $data[$read & $mask]
    set $read = $read + 1
end
set crash_log->read = $write

end
