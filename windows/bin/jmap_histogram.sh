#!/usr/bin/env bash

# Usage:
# ./$0 PID

set -eu

pid=$1
java_bin_path="/d/jdk-7u79-windows-x64/bin"
dump_file="$HOME/jmap_$pid"
touch "$dump_file"
"$java_bin_path"/jmap -permstat "$pid" > "$dump_file"

echo "# Total:"
grep live "$dump_file" |tail -n +3 | awk '{s+=$3} END{print s}'

echo "# Histogram:"
histogram_file="$dump_file"".hist"
cat "$dump_file" | tail -n +3 | awk '{print $6" "$3}' > "$histogram_file"
jmap_histogram.py "$histogram_file"

echo "# Heap Dump:"
hprof_file="$dump_file".hprof
"$java_bin_path"/jmap -dump:file="$hprof_file" "$pid"
"$java_bin_path"/jhat -port 9091 "$hprof_file"
