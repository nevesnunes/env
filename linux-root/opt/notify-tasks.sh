#!/bin/bash

#user=$(id -n -u)
user=${user:-fn}

log_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
mkdir -p "$log_dir"
log_file="$log_dir/$(basename "$0")"
date '+%Y-%m-%d_%H-%M-%S' > "$log_file"
exec  > >(tee -ia "$log_file")
exec 2> >(tee -ia "$log_file" >&2)
exec 9> "$log_file"
BASH_XTRACEFD=9

set -eux

display=$(ps -aeux --no-header | \
  grep "^$user.*DISPLAY=[0-9A-Za-z:]*" | \
  sed 's/.*DISPLAY=\([0-9A-Za-z:]*\).*/\1/g' | \
  head -n1)
export DISPLAY=$display

export PATH="/bin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"

function notify() {
  due_result="$(echo "$1" | head -n 1)"
  if echo "$due_result" | grep -qi "No matches"; then
    tasks=$(echo "$1" | \
      tail -n +4 | \
      head -n -2 | \
      sed "s/^ \+//" | \
      sed "s/  \+/ /" | \
      cut -d' ' -f "$3")
    notify-send "$2" "$tasks"
  fi
}

# Force a sync
sync_dummy="/home/$user/Dropbox/deploy/sync.dummy"
echo "sync" > "$sync_dummy"
sleep 5
rm "$sync_dummy"

# Wait for syncing to be complete
TRIES=20
while [[ $TRIES -gt 0 ]]; do
	STATUS="$(dropbox status)"
	if [[ ("$STATUS" == "Idle") || ("$STATUS" == "Up to date") ]]; then
		break
  else
    TRIES=$(($TRIES - 1))
    sleep 5
  fi
done

if [ $TRIES -eq 0 ]; then
  echo "[$(basename "$0")] Warning" "Skipping tasks notification: not synced." >&2
  exit 1
fi

if [ -z "$1" ]; then
  notify "$(task simple due.before:tomorrow 2>&1)" "Tasks due:" "2-10"
  notify "$(task simple due:tomorrow 2>&1)" "Tasks for tomorrow:" "2-10"
fi
while [ "$1" != "" ]; do
  case $1 in
  -r|--range)
    shift
    notify "$(task simple "$1" 2>&1)" "Tasks soon:" "2-10"
    exit 0
  esac
  shift
done
