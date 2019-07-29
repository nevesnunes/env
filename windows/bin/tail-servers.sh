#!/usr/bin/env bash

set -eu

pattern=$*

# Syntax:
# (server log [server log ...])
in=( \
  foo1a foo2a \
  foo1b foo2b
)

function tail_over_ssh() {
server=$1
shift
log=$1
shift

cat <<- EOF > ./"logs_$log.expect"
#!/usr/bin/expect -f
spawn ssh "$server" -t "tail -f /var/log/$log/SystemOut.log | grep -v \"$*\""
expect {
  -re ".*sword.*" {
    exp_send "bar\r"
  }
  -re ".*es.*o.*" {
    exp_send "yes\r"
    exp_continue
  }
}
while true {
  expect eof
}
EOF

./"logs_$log.expect" && rm ./"logs_$log.expect"
}

length=${#in[*]}
for ((i=0; i<$length; i+=2)); do
  server=foo@${in[$i]}.com
  log=${in[$(($i+1))]}
  tail_over_ssh "$server" "$log" "$pattern" &
done

for job in $(jobs -p)
do
    wait "$job" || echo "job $job failed!"
done

cleanup() {
    echo "[$(basename "$0")] Killing jobs..."
    for job in $(jobs -p)
    do
        kill "$job"
    done
}
trap cleanup EXIT INT QUIT TERM

read -r -n1 -p "Press any key to exit..."
