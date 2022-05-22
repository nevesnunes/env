#!/usr/bin/env bash

set -eu

user=${USER:-$(id -nu)}
pass=${PASS:-}
pattern=$*

# Syntax:
# (server log [server log ...])
in=(
  server1 log1
  server2 log2
)

function tail_remote_file() {
  server=$1
  shift
  log=$1
  shift

  cat <<- EOF > ./"logs_$log.expect"
#!/usr/bin/expect -f
spawn ssh "$server" -t "tail -f /var/log/$log/SystemOut.log | grep -i \"$*\""
expect {
  -re ".*sword.*" {
    exp_send "$pass\r"
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

  ./"logs_$log.expect"
  rm -f ./"logs_$log.expect"
}

length=${#in[*]}
for ((i = 0; i < $length; i += 2)); do
  server=$user@${in[$i]}
  log=${in[$(($i + 1))]}

  tail_remote_file "$server" "$log" "$pattern" &
done

cleanup() {
  for job in $(jobs -p); do
    kill "$job"
  done
}
trap cleanup EXIT INT QUIT TERM

for job in $(jobs -p); do
  wait "$job" || echo "$job failed!"
done

read -r -n1 -p "Press any key to exit..."
