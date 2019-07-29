#!/usr/bin/awk -f

BEGIN {
    suffix_counter = 1
}
/start_pattern/ {
    is_buffered = 1
}
is_buffered {
    buffer ? buffer = buffer"\n"$0 : buffer = $0
}
/end_pattern/ {
    is_buffered = 0
    print buffer > "out-"suffix_counter
    suffix_counter++
    buffer = ""
}
