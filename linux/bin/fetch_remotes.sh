#!/usr/bin/env bash

set -eu

user=${USER:-$(id -nu)}
pass=${PASS:-}

# Syntax:
# (server log [server log ...])
in=(
  server1 log1
  server2 log2
)

function fetch_remote_file() {
  server=$1
  shift
  remote_file=$1
  shift
  output_file=${log//[\/]/_}

  cat <<- EOF > ./"$output_file.expect"
#!/usr/bin/expect -f
spawn scp "$server:$remote_file" "$output_file"
expect {
  -re ".*sword.*" {
    exp_send "$pass\r"
  }
  -re ".*es.*o.*" {
    exp_send "yes\r"
    exp_continue
  }
}
interact
EOF

  ./"$output_file.expect" && rm -f ./"$output_file.expect"
}

length=${#in[*]}
for ((i = 0; i < $length; i += 2)); do
  server=$user@${in[$i]}
  log=${in[$(($i + 1))]}

  fetch_remote_file "$server" "/var/log/$log/SystemOut.log"
  fetch_remote_file "$server" "/var/log/$log/SystemErr.log"
  fetch_remote_file "$server" http_access.log
done
