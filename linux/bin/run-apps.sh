#!/usr/bin/env bash

log_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
mkdir -p "$log_dir"
log_file="$log_dir/$(basename "$0").$$"
touch "$log_file"
exec  > >(tee -ia "$log_file")
exec 2> >(tee -ia "$log_file" >& 2)
exec 9> "$log_file"
BASH_XTRACEFD=9

set -x

function contains() {
  local n=$#
  local value=${!n}
  for ((i=1;i < $#;i++)); do
    if [ "${!i}" == "${value}" ]; then
      return 0
    fi
  done
  return 1
}

function switch_to_main_workspace {
  main_workspace=2

  # HACK: gnome-shell will segfault when switching workspaces while
  # the compositor isn't created, so we need to wait for it.
  # See: https://gitlab.gnome.org/GNOME/mutter/issues/339
  if wmctrl -m | grep -qi gnome; then
    TRIES=10
    while [ $TRIES -gt 0 ]; do
      if /home/"$USER"/bin/check-compositor/check-compositor | greq -q 1; then
        break
      fi
      sleep 1
      TRIES=$(($TRIES - 1))
    done
    if [ $TRIES -eq 0 ]; then
      return
    fi
  fi

  wmctrl -s $main_workspace
}

function run-app-with-net {
  TRIES=10
  while ! ping google.com -c 1 &>/dev/null && \
      [ $TRIES -gt 0 ]; do
    sleep 2

    TRIES=$(($TRIES - 1))
  done

  run-app "$@"
}

processed_ids=()
function run-app {
  app=$1
  workspace=$2
  tile=$3

  # Extract command from generic name
  app_command=($app)
  app="${app_command[0]}"
  if echo "$app" | grep -qi "browser"; then
    app_command=("user-browser")
    browser=$(xdg-mime query default x-scheme-handler/http)
    if echo "$browser" | grep -qi "firefox"; then
      app="firefox"
    else
      app="google-chrome"
    fi
  elif echo "$app" | grep -qi "terminal"; then
    app=$(readlink "$(command -v user-terminal)")
  fi

  app_command+=("&>/dev/null &disown")

  # Launch and wait for any instance of class
  eval "${app_command[@]}"
  TRIES=60
  while [ -z $(wmctrl -lx | \
      cut -d' ' -f-4 | \
      grep -i "$app" | \
      cut -d' ' -f1) ] && \
        [ $TRIES -gt 0 ]; do
    sleep 2

    TRIES=$(($TRIES - 1))
  done

  TRIES=10
  while [ $TRIES -gt 0 ]; do
    sleep 2
    
    # Move all instances to passed workspace
    ids=$(wmctrl -lx | \
        cut -d' ' -f-4 | grep -i "$app" | cut -d' ' -f1)
    while read -r id; do
      # Skip windows we already moved
      contains "${processed_ids[@]}" "$id"
      if [ $? -eq 1 ]; then
        processed_ids+=("$id")
        wmctrl -i -r "$id" -t "$workspace"

        if [ -n "$tile" ]; then
          xsize.sh --id "$id" "$tile"
        fi
      fi
    done <<< "$ids"

    TRIES=$(($TRIES - 1))
  done

  return
}

# Run app passed as argument instead of pre-defined apps
app=$1
workspace=$2
tile=$3
if [ -n "$app" ] && [ -n "$workspace" ]; then
  wmctrl -s "$workspace"
  run-app "$app" "$workspace" "$tile" &
  exit 0
fi

# Run pre-defined apps
for i in /home/fn/Dropbox/doc/goals/*.md; do
  name=$(basename "$i" | sed 's/\.md/usr/g')
  swapfile=$(find ~/tmp/ -iname "$name*" | head -n1)
  if [ -n "$swapfile" ]; then
    mv "$swapfile" ~/tmp/"$name.bswp"
    rm -f ~/tmp/"$name".sw* &>/dev/null
  fi
done
task_keys=("\"tl\"" C-m)
vim_keys=("\"cd /home/fn/Dropbox/doc/goals && vim "'*'".md -c 'e next.md'\"" C-m)

switch_to_main_workspace &

run-app-with-net thunderbird 1 -h &
run-app-with-net browser 2 -h &

# Sequential launches of same app
run-app "user-terminal.sh tmux new-session \\; send-keys ${task_keys[*]}" 1 -l
run-app "user-terminal.sh tmux new-session \\; send-keys ${vim_keys[*]} \\; new-window" 2 -l

# Give time for panel to start
# sleep 2
# run-app-with-net skype 0 &
