#!/usr/bin/env sh

file="$XDG_RUNTIME_DIR/bin/xapp.data"
mkdir -p "$(dirname "$file")"
touch "$file"

number='^\(0x\)*[0-9a-f]\+$'
focus_window() {
  target_window=$1
  if echo "$target_window" | grep -qi "$number"; then
    if ! xdotool windowactivate "$target_window"; then
      return 1
    else
      exit 0
    fi
  fi
}

find_window_to_focus() {
  desktop=$1
  app_class=$2
  active_window=$(xdotool getactivewindow)
  target_window=""
  # shellcheck disable=SC2046
  set -- $(xdotool search --desktop "$desktop" --class "$app_class")
  while [ "$1" != "" ]; do
    candidate_window=$1
    shift
    echo "$candidate_window" | grep -qi "$active_window" && continue
    target_window=$candidate_window
  done
  target_window=${target_window:-$candidate_window}
  focus_window "$target_window"
}

notify() {
  icon='/usr/share/icons/Adwaita/scalable/actions/focus-windows-symbolic.svg'
  if [ -f "$icon" ]; then
    notify-send -i "$icon" "$1" "$2"
  else
    notify-send "$1" "$2"
  fi
}

set_mark() {
  focus_id=$(xdotool getwindowfocus)
  echo "$focus_id" > "$file"
  window_name=$(xdotool getwindowname "$focus_id")
  notify "Marked" "$window_name"
  exit 0
}

get_mark() {
  line=$(head -n 1 "$file")
  if [ -n "$line" ]; then
    focus_window "$line"

    # Marked window was killed
    if [ $? -eq 1 ]; then
      set_mark
    fi
  else
    # No saved mark
    set_mark
  fi
}

input=""
iterate=""
while [ "$1" != "" ]; do
  case $1 in
    -a|set-above)
      wmctrl -r :ACTIVE: -b add,above,sticky
      exit 0
      ;;
    -n|set-normal)
      wmctrl -r :ACTIVE: -b remove,above,sticky
      exit 0
      ;;
    -s|set-mark)
      set_mark
      exit 0
      ;;
    -g|get-mark)
      get_mark
      exit 0
      ;;
    -i|iterate)
      iterate=1
      ;;
    *)
      input=$1
      ;;
  esac
  shift
done

# Extract class name
app_class=$input
if echo "$app_class" | grep -qi "browser"; then
  app_class=$(basename \
    "$(readlink -f \
    "$(command -v user-browser)")")
elif echo "$app_class" | grep -qi "term"; then
  app_class="$app_class|rxvt"
fi

# Give priority to a window in the current workspace
desktop=$(xdotool get_desktop)
find_window_to_focus "$desktop" "$app_class"

# Iterate through all workspaces
if [ -n "$iterate" ]; then
  desktops=$(xdotool get_num_desktops)
  i=0
  while [ $((i<$desktops)) -ne 0 ]; do
    find_window_to_focus "$i" "$app_class"
    i=$((i+1))
  done
fi

# Window not present, therefore launch app
if echo "$input" | grep -qi "browser"; then
  nohup user-browser &
elif echo "$app_class" | grep -qi "term"; then
  nohup user-terminal.sh tmux &
else
  nohup $app_class &
fi
