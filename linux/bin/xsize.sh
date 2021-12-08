#!/usr/bin/env bash

# Validation:
# - WM supports X11: objdump -T /usr/bin/i3 | grep 'XInternAtom\|xcb_intern_atom'
# - WM supports EWMH: 
# readelf -p .rodata /usr/bin/i3 | grep _NET_WM_NAME
# || using libbfd, reference: https://stackoverflow.com/questions/1685483/how-can-i-examine-contents-of-a-data-section-of-an-elf-file-on-linux
# objcopy /usr/bin/i3 /dev/null --dump-section .rodata=/dev/stdout | grep _NET_WM_NAME
# || hex dump
# objdump -s -j .rodata /usr/bin/i3 | tail -n +5 | sed 's/.*\(.\{16\}\)$/\1/g' | paste -s -d '' | grep _NET_WM_NAME
# Case Studies:
# - https://unix.stackexchange.com/questions/594903/are-basic-posix-utilities-parallelized
# - https://stackoverflow.com/questions/384121/creating-a-module-system-dynamic-loading-in-c
# ~/code/snippets/dlsym.c

# TODO:
# - Check _NET_WM_NAME loaded before intern atom calls
#     - With static analysis?

tmp_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
mkdir -p "$tmp_dir"
chmod 700 "$tmp_dir"
data_file="$tmp_dir/xtilefactor.data"
log_file="$tmp_dir/xsize.log"
touch "$data_file" "$log_file"

number='^(0x)*[0-9a-f]+(\.[0-9])?$'

session=$(wmctrl -m | head -n1 | awk '{print $2}')

# /!\ WARNING /!\ Support is still experimental
GAP_SIZE=0

# Pixels for decrementing/incrementing window size
RESIZE_STEP=75

DEBUG=0
TMP="$tmp_dir/$(date +'%s')"

function set_tile_factors {
  notify=true

  # Passed factor as argument 
  if [[ -n $1 ]]; then
    factor=$1
    notify=false
    echo "$factor" > "$data_file"
  else
    # Read factor from saved state
    factor=$(head -n 1 "$data_file")
    if [ "$factor" != "" ]; then
      if [[ $factor -eq 50 ]]; then
        factor=65
      else
        factor=50
      fi
      echo "$factor" > "$data_file"
    # Set default factor
    else
      factor=50
      echo "$factor" > "$data_file"
    fi
  fi

  master_factor=$factor
  slave_factor=$((100 - $master_factor))
    
  if [[ $notify == true ]]; then
    notify-send "[$basename] Info:" "Set Tile Factor = $factor"
  fi
}

function reset_tile_factors {
  set_tile_factors 50
}

function make_desktop_geometry {
  line=$(head -n 1 "$data_file")
  if [ "$line" != "" ]; then
    master_factor="$line"
    slave_factor=$((100 - $master_factor))
  else
    reset_tile_factors
  fi

  # TODO: Support multi-monitor: Need to get active window's screen.
  # Note: `mawk` does not support regex interval operators, need to match 1 or more characters.
  geo=$(xrandr | awk '
    /[[:space:]]connected/ {
      r = match($0, "[0-9]+x[0-9]+\\+0\\+0");
      if (r > 0) print substr($0, RSTART, RLENGTH - 4);
    }
  ')
  geo_desktop=$(echo -e "$geo" | sed -n 1p)
  w=$(echo -e "$geo_desktop" | cut -d'x' -f1)
  h=$(echo -e "$geo_desktop" | cut -d'x' -f2)

  # wmctrl may omit the second dimensions
  geo=$(wmctrl -d | grep '\*' | grep -Eho '[0-9]{3,4}x[0-9]{3,4}')
  geo_workarea=$(echo -e "$geo" | sed -n 2p)
  if [ -z $geo_workarea ]; then
    geo_workarea=$geo
  fi

  # TODO: wmctrl reports smallest workarea given multiple screens, detect it by finding single screen with combined width of all screens (may not work on vertically arranged screens)
  w_workarea=$(echo -e "$geo_workarea" | cut -d'x' -f1)
  if [ "$w" -lt "$w_workarea" ]; then
    h_workarea=$h
  else
    h_workarea=$(echo -e "$geo_workarea" | cut -d'x' -f2)
  fi
  geo_offset=$(wmctrl -d | grep '\*' | grep -Eho '[0-9]+,[0-9]+')

  # wmctrl may omit the second dimensions
  geo_workarea_offset=$(echo -e "$geo_offset" | sed -n 2p)
  if [[ -z $geo_workarea_offset ]]; then
    geo_workarea_offset=$geo_offset
  fi

  h_workarea_offset=$(echo -e "$geo_workarea_offset" | cut -d',' -f2)
  workarea_factor=$(($h - $h_workarea))
  echo "workarea_factor = $workarea_factor = $h - $h_workarea"
  minor_workarea_factor=$(($workarea_factor * $minor_h_factor / 100))

  echo "geo: $w $h (offset: $h_workarea_offset)"
}

function make_window_geometry {
  local window_id
  window_id=$1

	# Calculate borders accurately with unmaximized window
  wmctrl -i -r "$window_id" -b remove,maximized_vert,maximized_horz

  minor_w=$(($w * $minor_w_factor / 100))
  minor_h=$(($h * $minor_h_factor / 100))
  master_w=$(($w * 65 / 100 - 1))
  slave_w=$(($w * 35 / 100 - 1))
  master_factor_w=$(($w * $master_factor / 100))
  slave_factor_w=$(($w * $slave_factor / 100))

  window_geo=$(xdotool getwindowgeometry "$window_id" \
      | sed -n 3p | cut -d' ' -f4)
  window_w=$(($(echo "$window_geo" | cut -d'x' -f1)))
  window_h=$(($(echo "$window_geo" | cut -d'x' -f2)))
  window_base_h=$window_h

  # We retrieve absolute coordinates with `xdotool`, in case
  # coordinates are set to zero in `xwininfo`
  window_pos_abs=$(xdotool getwindowgeometry "$window_id" \
      | sed -n 2p | cut -d' ' -f4)
  window_pos=$(xwininfo -id "$window_id")
  window_pos_rel_x=$(echo "$window_pos" | grep -i "Relative upper-left X" | sed 's/.*:[ \t\n]*//')
  window_pos_rel_y=$(echo "$window_pos" | grep -i "Relative upper-left Y" | sed 's/.*:[ \t\n]*//')
  window_x=$(($(echo "$window_pos_abs" | cut -d',' -f1) - $window_pos_rel_x))
  window_y=$(($(echo "$window_pos_abs" | cut -d',' -f2) - $window_pos_rel_y))

  # Absolute x position to workaround GTK3 CSD window placement 
  move_x=0

  # Absolute y position relative to panels
  move_y=$((0 + $h_workarea_offset))
  h_bottom_workarea_offset=$(($workarea_factor - $h_workarea_offset))
  adjusted_move_y=$(( $((- $h_bottom_workarea_offset + $h_workarea_offset)) / 2 ))

  # Include GTK3 CSD frame properties (they are relevant for window geometry)
  frame=$(xprop -id "$window_id" | grep _GTK_FRAME_EXTENTS)
  if [[ "$frame" != "" ]]; then
    frame_left=$(echo   "$frame" | cut -d' ' -f3 | cut -d',' -f1)
    frame_right=$(echo  "$frame" | cut -d' ' -f4 | cut -d',' -f1)
    frame_top=$(echo    "$frame" | cut -d' ' -f5 | cut -d',' -f1)
    frame_bottom=$(echo "$frame" | cut -d' ' -f6 | cut -d',' -f1)

    adjusted_h=$(($h - $workarea_factor + $frame_top + $frame_bottom))
    adjusted_minor_h=$(($minor_h - $minor_workarea_factor + $frame_top + $frame_bottom))
    adjusted_master_w=$(($master_w))
    adjusted_master_factor_w=$(($master_factor_w))

    w=$(($w + $frame_left + $frame_right))
    minor_w=$(($minor_w + $frame_left + $frame_right))
    minor_h=$(($minor_h + $frame_top + $frame_bottom))
    master_w=$(($master_w + $frame_left + $frame_right))
    slave_w=$(($slave_w + $frame_left + $frame_right))

    master_factor_w=$(($master_factor_w + $frame_left + $frame_right))
    slave_factor_w=$(($slave_factor_w + $frame_left + $frame_right))

    window_h=$(($window_h + $workarea_factor + $frame_top + $frame_bottom))

    move_x=$((- $frame_left))
    move_y=$((- $frame_top))
    adjusted_move_x=0
    adjusted_move_y=$(($adjusted_move_y + $frame_bottom + $frame_top))
  else
    # Exclude SSD frame properties
    frame=$(xprop -id "$window_id" | grep _NET_FRAME_EXTENTS)
    if [[ "$frame" != "" ]]; then
      frame_left=$(echo   "$frame" | cut -d' ' -f3 | cut -d',' -f1)
      frame_right=$(echo  "$frame" | cut -d' ' -f4 | cut -d',' -f1)
      frame_top=$(echo    "$frame" | cut -d' ' -f5 | cut -d',' -f1)
      frame_bottom=$(echo "$frame" | cut -d' ' -f6 | cut -d',' -f1)
    # Custom decorations (ex.: Google Chrome) or a window manager
    # that doesn't set frame extents. We will make assumptions about
    # the borders and expect the relative coordinates to be populated.
    else
      frame_left=$window_pos_rel_x
      frame_right=$window_pos_rel_x
      frame_top=$window_pos_rel_y
      frame_bottom=$window_pos_rel_x
    fi

    adjusted_h=$(($h - $workarea_factor - $frame_top - $frame_bottom))
    echo "adjusted_h = $adjusted_h = $h - $workarea_factor - $frame_top - $frame_bottom"
    adjusted_minor_h=$(($minor_h - $minor_workarea_factor - $frame_top - $frame_bottom))
    adjusted_master_w=$(($master_w))
    adjusted_master_factor_w=$(($master_factor_w))

    w=$(($w - $frame_left - $frame_right))
    minor_w=$(($minor_w - $frame_left - $frame_right))
    minor_h=$(($minor_h - $frame_top - $frame_bottom))
    master_w=$(($master_w - $frame_left - $frame_right))
    slave_w=$(($slave_w - $frame_left - $frame_right))
    
    master_factor_w=$(($master_factor_w - $frame_left - $frame_right))
    slave_factor_w=$(($slave_factor_w - $frame_left - $frame_right))

    window_h=$(($window_h + $workarea_factor + $frame_top + $frame_bottom))

    adjusted_move_x=$(($frame_left + $frame_right))
    adjusted_move_y=$(($adjusted_move_y + $frame_bottom + $frame_top))
  fi

  # Invisible borders will interfere with position, so
  # we use an offset
  right_move_x=$move_x
  adjusted_right_move_x=$adjusted_move_x
  if echo "$session" | grep -q -i "GNOME"; then
    right_move_x=$((-$right_move_x - 1))
    adjusted_right_move_x=$((-$adjusted_right_move_x + 1))
  fi

  # Some window managers force `StaticGravity` on windows, so
  # we need to compensate its effect on positioning
  if echo "$session" | grep -q -i "IceWM"; then
    gravity=$(xprop -id "$window_id" | grep -i "gravity")
    if echo "$gravity" | grep -q -i "static"; then
      move_y=$(($move_y + $frame_top))
      adjusted_move_y=$(($adjusted_move_y + $frame_top))
    fi
  fi

  # Compensate normal gravities
  adjusted_window_x=$(($window_x - $frame_left))
  adjusted_window_y=$(($window_y))
  if echo "$session" | grep -q -i "openbox"; then
    adjusted_window_y=$(($adjusted_window_y - $frame_top))
  fi

  # Constants used throughout the code, due to `wmctrl` not
  # being consistent with `-1` values
  PRESERVED_X=$(($adjusted_window_x - $GAP_SIZE))
  PRESERVED_Y=$(($adjusted_window_y - $GAP_SIZE))
  PRESERVED_W=$(($window_w + $GAP_SIZE * 2))
  PRESERVED_H=$(($window_base_h + $GAP_SIZE * 2))
  
  echo "window: $PRESERVED_X $PRESERVED_Y $PRESERVED_W $PRESERVED_H"
}

function make_geometry {
  make_desktop_geometry
  make_window_geometry "$1"
}

function output_geometry {
  # Adjust position so that it outputs window contents without frames
  echo "$PRESERVED_W""x""$PRESERVED_H $PRESERVED_X"",""$(($PRESERVED_Y + $frame_top))"
}

requested_prorations=()
function put_and_prorate {
  put_window_by_id "$2" "$3" "$4" "$5" "$6" "$7"
  requested_prorations+=("$4,$5,$6,$7,$1,$2")
}

function draw_windows {
  if [[ "$DEBUG" -eq 1 ]]; then
    info="[ { 'w': $w, 'h': $h }"
    ids=$(wmctrl -lx | \
        awk -v cdt="$current_desktop" '$2 == cdt {print $1" "$3}' | \
        cut -d' ' -f1)
    while read -r id; do
      make_window_geometry "$id"
      decimal_id=$(printf "%d" "$id")
      info+=", {'id': $decimal_id, 'x': $PRESERVED_X, 'y': $PRESERVED_Y, 'w':$PRESERVED_W, 'h':$PRESERVED_H }"
    done <<< "$ids"
    info+=" ]"
    echo -n "$info" | sed 's/'"'"'/"/g' > "$TMP"
    ./draw-windows.py "$TMP"
    rm "$TMP"
    exit 2
  fi
}

# FIXME
function process_requested_prorations {
  draw_windows
  temporary_prorations=("${requested_prorations[@]}")
  for (( i=0; i<"${#temporary_prorations[@]}"; i++ )); do
    requested_prorations=("${requested_prorations[@]:1}")
    request="${temporary_prorations[$i]}"
    request_array=(${request/usr/,/ })
    prorate_other_windows "${request_array[@]}"
  done
}

function put_window_by_id {
  if [[ "$DEBUG" -eq 1 ]]; then
    echo "put|id:$1"
    return
  fi

  # Remove maximized state to allow resizing
  wmctrl -i -r "$1" -b remove,maximized_vert,maximized_horz

  local new_x=$(($3 + $GAP_SIZE))
  local new_y=$(($4 + $GAP_SIZE))
  local new_width=$(($5 - $GAP_SIZE * 2))
  if [[ $new_width -lt 0 ]]; then
      new_width=$PRESERVED_W
  fi
  local new_height=$(($6 - $GAP_SIZE * 2))
  if [[ $new_height -lt 0 ]]; then
      new_height=$PRESERVED_H
  fi
  wmctrl -i -r "$1" -e "$2,$new_x,$new_y,$new_width,$new_height"
  echo "put window cmd: wmctrl -i -r $1 -e $2,$new_x,$new_y,$new_width,$new_height"
}

function put_other_windows {
  # TODO: class not working for browser windows
  return 1;

  # Extract command from generic name
  browser=$(xdg-mime query default x-scheme-handler/http)
  if echo "$browser" | grep -q -i "firefox"; then
    browser="firefox"
  else
    browser="google-chrome"
  fi

  # Convert xdotool id format to wmctrl id format
  window_hex_id=$(printf 0x%.8x "${window_id%.*}")

  # Fail if reading garbage
  if ! [[ "$window_hex_id" =~ $number ]] ; then
    basename=$(basename "$0")
    echo "[$basename $(date +'%s')] Error: Invalid window id read: $window_hex_id" >> "$log_file"
    exit 1
  fi

  # Skip if not one of the involved windows
  current_app=$(wmctrl -lx | grep "$window_hex_id" | grep -i -E "$apps")
  if [[ -z "$current_app" ]]; then
    return 1;
  fi

  # Extract all windows in the current desktop 
  current_desktop=$(echo "$current_app" | awk '{print $2}')
  current_class=$(echo "$current_app" | awk '{print $3}')
  other_apps=$(wmctrl -lx | \
      awk -v cdt="$current_desktop" '$2 == cdt {print $1" "$3}' | \
      grep -i -E "$apps")
  while read -r other_app; do
    id=$(echo "$other_app" | awk '{print $1}')
    target_class=$(echo "$other_app" | awk '{print $2}')
 
    # Don't move a focused window or a window of the same class
    if [[ "$window_hex_id" != "$id" ]] && [[ "$target_class" != "$current_class" ]]; then
      # Remove maximized state to allow resizing
      put_window_by_id "$id" "$1" "$2" "$3" "$4" "$5"
   fi
  done <<< "$other_apps"
}

function prorate_other_windows {
  current_window_x=$1
  current_window_y=$2
  current_window_w=$3
  current_window_h=$4
  current_window_direction=$5

  # Convert xdotool id format to wmctrl id format
  window_hex_id=$(printf 0x%.8x "$window_id")

  # Fail if reading garbage
  if ! [[ "$window_hex_id" =~ $number ]] ; then
    basename=$(basename "$0")
    echo "[$basename $(date +'%s')] Error: Invalid window id read: $window_hex_id" >> "$log_file"
    exit 1
  fi

  current_app=$(wmctrl -lx | grep "$window_hex_id")
  if [[ -z "$current_app" ]]; then
    return 1;
  fi

  # Extract ids from all windows in the current desktop 
  current_desktop=$(echo "$current_app" | awk '{print $2}')
  ids=$(wmctrl -lx | \
      awk -v cdt="$current_desktop" '$2 == cdt {print $1" "$3}' | \
      cut -d' ' -f1)
  while read -r id; do
    # Don't move a focused window
    if [[ "$window_hex_id" != "$id" ]]; then
      make_window_geometry "$id"

      # Is there y-overlap with the target window?
      # Test with a XOR, since only one of the y-directions has an overlap
      window_y_from_bottom_diff=$(( $(($window_y + $window_h)) - $workarea_factor \
            - $current_window_y))
      window_y_from_top_diff=$(( $(($current_window_y + $current_window_h)) + $workarea_factor \
            - $window_y))
      if [[ $current_window_y -lt $window_y ]]; then
        window_y_from_bottom_diff_to_compare=$((- $window_y_from_bottom_diff))
        window_y_from_top_diff_to_compare=$window_y_from_top_diff
      else
        window_y_from_bottom_diff_to_compare=$window_y_from_bottom_diff
        window_y_from_top_diff_to_compare=$((- $window_y_from_top_diff))
      fi
      if ([[ $window_y_from_top_diff_to_compare -gt 0 ]] || \
          [[ $window_y_from_bottom_diff_to_compare -gt 0 ]]) && ! ( \
          [[ $window_y_from_top_diff_to_compare -gt 0 ]] && \
          [[ $window_y_from_bottom_diff_to_compare -gt 0 ]]); then
        # Is there x-overlap with the target window?
        # Test with a XOR, since only one of the x-directions has an overlap
        window_x_from_right_diff=$(( $(($current_window_x + $current_window_w)) \
              - $window_x))
        window_x_from_left_diff=$(( $(($window_x + $window_w)) \
              - $current_window_x))
        if [[ $current_window_x -lt $window_x ]]; then
          window_x_from_right_diff_to_compare=$((- $window_x_from_right_diff))
          window_x_from_left_diff_to_compare=$window_x_from_left_diff
        else
          window_x_from_right_diff_to_compare=$window_x_from_right_diff
          window_x_from_left_diff_to_compare=$((- $window_x_from_left_diff))
        fi
        if ([[ $window_x_from_right_diff_to_compare -gt 0 ]] || \
            [[ $window_x_from_left_diff_to_compare -gt 0 ]]) && ! ( \
            [[ $window_x_from_right_diff_to_compare -gt 0 ]] && \
            [[ $window_x_from_left_diff_to_compare -gt 0 ]]); then
          # Change in x-direction
          if [[ "$current_window_direction" == "w" ]]; then
            # Extract diff from the direction that caused overlap
            # DIRECTION: ->
            if ! [[ $window_x_from_right_diff_to_compare -gt 0 ]]; then
              window_x_diff=$window_x_from_right_diff
              # No more space to move
              if [[ $(($window_x + $window_w + $window_x_diff)) -gt $w ]]; then
                put_and_prorate "$current_window_direction" "$id" "1" \
                    "$(($w - $(($window_w - $move_x)) + $window_x_diff + $frame_left + $frame_right + $adjusted_right_move_x))" \
                    "$PRESERVED_Y" \
                    "$(($window_w - $window_x_diff - $frame_left - $frame_right ))" \
                    "$PRESERVED_H"
              else
                put_and_prorate "$current_window_direction" "$id" "1" \
                    "$(($window_x + $window_x_diff + $frame_left))" \
                    "$PRESERVED_Y" \
                    "$PRESERVED_W" \
                    "$PRESERVED_H"
              fi
            # DIRECTION: <-
            elif ! [[ $window_x_from_left_diff_to_compare -gt 0 ]]; then
              window_x_diff=$window_x_from_left_diff
              # No more space to move
              if [[ $(($window_x - $window_x_diff)) -lt 0 ]]; then
                put_and_prorate "$current_window_direction" "$id" "1" \
                    "$move_x" \
                    "$PRESERVED_Y" \
                    "$(($window_w - $window_x_diff - $frame_left))" \
                    "$PRESERVED_H"
              else
                put_and_prorate "$current_window_direction" "$id" "1" \
                    "$(($window_x - $window_x_diff - $adjusted_right_move_x))" \
                    "$PRESERVED_Y" \
                    "$PRESERVED_W" \
                    "$PRESERVED_H"
              fi
            fi
          # Change in y-direction
          else
            # Extract diff from the direction that caused overlap
            # DIRECTION: ^
            if [[ $window_y_from_bottom_diff_to_compare -gt 0 ]]; then
              window_y_diff=$window_y_from_bottom_diff
              if [[ $(($window_y - $window_y_diff)) -lt 0 ]]; then
                put_and_prorate "$current_window_direction" "$id" "1" \
                    "$PRESERVED_X" \
                    "$(($move_y))" \
                    "$PRESERVED_W" \
                    "$(($window_base_h - $window_y_diff + $frame_top))"
              else
                put_and_prorate "$current_window_direction" "$id" "1" \
                    "$PRESERVED_X" \
                    "$(($adjusted_window_y - $window_y_diff + $frame_top))" \
                    "$PRESERVED_W" \
                    "$PRESERVED_H"
              fi
            # DIRECTION: V
            elif [[ $window_y_from_top_diff_to_compare -gt 0 ]]; then
              window_y_diff=$window_y_from_top_diff
              if [[ $(($window_y + $window_base_h + $window_y_diff)) -gt $h ]]; then
                put_and_prorate "$current_window_direction" "$id" "1" \
                    "$PRESERVED_X" \
                    "$(($h - $window_h - $workarea_factor + $frame_bottom + $frame_top + $window_y_diff))" \
                    "$PRESERVED_W" \
                    "$(($window_base_h + $workarea_factor - $frame_bottom - $frame_top - $window_y_diff))"
              else
                put_and_prorate "$current_window_direction" "$id" "1" \
                    "$PRESERVED_X" \
                    "$(($adjusted_window_y - $workarea_factor + $frame_bottom + $frame_top + $window_y_diff))" \
                    "$PRESERVED_W" \
                    "$(($window_base_h - $frame_bottom))"
              fi
            fi
          fi
        fi
      fi
    fi
  done <<< "$ids"
  if [[ "$DEBUG" -eq 1 ]]; then
    for (( i=0; i<"${#requested_prorations[@]}"; i++ )); do
      request="${requested_prorations[$i]}"
      request_array=(${request/usr/,/ })
      echo "req|id:${request_array[5]}|x:$(printf '%4s' ${request_array[0]})|y:$(printf '%4s' ${request_array[1]})|w:$(printf '%4s' ${request_array[2]})|h:$(printf '%4s' ${request_array[3]})|dir:${request_array[4]}"
    done
    process_requested_prorations
  fi
}

if [[ "$1" == "--title" ]]; then
  shift
  window_id=$(wmctrl -l | grep -E "$1" | awk '{print $1}')
  shift
elif [[ "$1" == "--id" ]]; then
  shift
  window_id="$1"
  shift
else
  window_id="$(xdotool getactivewindow)"
fi

# Fail if reading garbage
if ! [[ "$window_id" =~ $number ]] ; then
  basename=$(basename "$0")
  echo "[$basename $(date +'%s')] Error: Invalid window id passed as argument: $window_id" >> "$log_file"
  exit 1
fi

minor_w_factor=$((100 / 2))
minor_h_factor=$((100 / 2))

if [ "$1" == "--tile-in-grid" ]; then
  shift
  if [[ "$#" -lt 4 ]]; then
    echo "Bad arguments"
    exit 1
  else
    tile_in_grid_x_index=$(($1 - 1))
    tile_in_grid_x_count=$2
    tile_in_grid_y_index=$(($3 - 1))
    tile_in_grid_y_count=$4

    minor_w_factor=$((100 / $tile_in_grid_x_count))
    minor_h_factor=$((100 / $tile_in_grid_y_count))

    make_geometry "$window_id"

    put_window_by_id "$window_id" 1 \
        $(($(($minor_w + $adjusted_right_move_x)) * $tile_in_grid_x_index)) \
        $(($(($minor_h + $adjusted_move_y)) * $tile_in_grid_y_index)) \
        $minor_w \
        $adjusted_minor_h

    exit 0
  fi
fi

make_geometry "$window_id"

if [ "$1" == "--output-geometry" ]; then
  output_geometry

  exit 0
fi

while [ "$1" != "" ]; do
  case $1 in
  -u)
    put_window_by_id "$window_id" 1 \
        $move_x $move_y \
        $master_factor_w $adjusted_minor_h
    ;;
  -i)
    put_window_by_id "$window_id" 1 \
        $(($adjusted_master_factor_w - $right_move_x)) $move_y \
        $slave_factor_w $adjusted_minor_h
    ;;
  -n)
    put_window_by_id "$window_id" 1 \
        $move_x $(($minor_h + $adjusted_move_y)) \
        $master_factor_w $adjusted_minor_h
    ;;
  -m)
    put_window_by_id "$window_id" 1 \
        $(($adjusted_master_factor_w - $right_move_x)) $(($minor_h + $adjusted_move_y)) \
        $slave_factor_w $adjusted_minor_h
    ;;
  -j)
    put_other_windows 1 \
        $move_x $move_y \
        $w $adjusted_minor_h
    put_window_by_id "$window_id" 1 \
        $move_x $(($minor_h + $adjusted_move_y)) \
        $w $adjusted_minor_h
    ;;
  -k)
    put_other_windows 1 \
        $move_x $(($minor_h + $adjusted_move_y)) \
        $w $adjusted_minor_h
    put_window_by_id "$window_id" 1 \
        $move_x $move_y \
        $w $adjusted_minor_h
    ;;
  -h)
    set_tile_factors 65
    put_other_windows 1 \
        $(($adjusted_master_w - $right_move_x)) $move_y \
        $slave_w $adjusted_h
    put_window_by_id "$window_id" 1 \
        $move_x $move_y \
        $master_w $adjusted_h
    ;;
  -l)
    set_tile_factors 65
    put_other_windows 1 \
        $move_x $move_y \
        $master_w $adjusted_h
    put_window_by_id "$window_id" 1 \
        $(($adjusted_master_w - $right_move_x)) $move_y \
        $slave_w $adjusted_h
    ;;
  -a|--half-left)
    set_tile_factors 50
    put_other_windows 1 \
        $(($minor_w + $adjusted_right_move_x)) $move_y \
        $minor_w $adjusted_h
    put_window_by_id "$window_id" 1 \
        $move_x $move_y \
        $minor_w $adjusted_h
    ;;
  -b|--half-right)
    set_tile_factors 50
    put_other_windows 1 \
        $move_x $move_y \
        $minor_w $adjusted_h
    put_window_by_id "$window_id" 1 \
        $(($minor_w + $adjusted_right_move_x)) $move_y \
        $minor_w $adjusted_h
    ;;
  --half-left-top)
    put_window_by_id "$window_id" 1 \
        $move_x $move_y \
        $minor_w $adjusted_minor_h
    ;;
  --half-left-bottom)
    put_window_by_id "$window_id" 1 \
        $move_x $(($minor_h + $adjusted_move_y)) \
        $minor_w $adjusted_minor_h
    ;;
  --half-right-top)
    put_window_by_id "$window_id" 1 \
        $(($minor_w + $adjusted_right_move_x)) $move_y \
        $minor_w $adjusted_minor_h
    ;;
  --half-right-bottom)
    put_window_by_id "$window_id" 1 \
        $(($minor_w + $adjusted_right_move_x)) \
        $(($minor_h + $adjusted_move_y)) \
        $minor_w $adjusted_minor_h
    ;;
  -c|--maximize)
    wmctrl -i -r "$window_id" -b toggle,maximized_vert,maximized_horz
    ;;
  -d|--move-top)
    put_window_by_id "$window_id" 1 \
        $PRESERVED_X $move_y \
        $PRESERVED_W $PRESERVED_H
    ;;
  -e|--move-bottom)
    put_window_by_id "$window_id" 1 \
        $PRESERVED_X $(($h - $window_h)) \
        $PRESERVED_W $PRESERVED_H
    ;;
  -f|--move-left)
    put_window_by_id "$window_id" 1 \
        $move_x $PRESERVED_Y \
        $PRESERVED_W $PRESERVED_H
    ;;
  -g|--move-right)
    put_window_by_id "$window_id" 1 \
        $(($w - $(($window_w - $move_x)) )) $PRESERVED_Y \
        $PRESERVED_W $PRESERVED_H
    ;;
  -z|--move-center)
    put_window_by_id "$window_id" 1 \
        $(( $(($w - $(($window_w - $move_x)) )) / 2)) \
        $(( $(($h - $window_h)) / 2)) \
        $PRESERVED_W \
        $PRESERVED_H
    ;;
  --decrement-up)
    put_window_by_id "$window_id" 1 \
        $PRESERVED_X $(($adjusted_window_y + $RESIZE_STEP)) \
        $PRESERVED_W $(($window_base_h - $RESIZE_STEP))
    ;;
  --decrement-down)
    put_window_by_id "$window_id" 1 \
        $PRESERVED_X $PRESERVED_Y \
        $PRESERVED_W $(($window_base_h - $RESIZE_STEP))
    ;;
  --decrement-left)
    put_window_by_id "$window_id" 1 \
        $(($adjusted_window_x + $(($RESIZE_STEP * 2)))) $PRESERVED_Y \
        $(($window_w - $(($RESIZE_STEP * 2)))) $PRESERVED_H
    ;;
  --decrement-right)
    put_window_by_id "$window_id" 1 \
        $PRESERVED_X $PRESERVED_Y \
        $(($window_w - $(($RESIZE_STEP * 2)))) $PRESERVED_H
    ;;
  --increment-up)
    window_new_y=$(($adjusted_window_y - $RESIZE_STEP))
    window_new_h=$(($window_base_h + $RESIZE_STEP))
    put_window_by_id "$window_id" 1 \
        $PRESERVED_X $window_new_y \
        $PRESERVED_W $window_new_h
    prorate_other_windows \
        $window_x $window_new_y $PRESERVED_W $window_new_h "h"
    ;;
  --increment-down)
    window_new_h=$(($window_base_h + $RESIZE_STEP))
    put_window_by_id "$window_id" 1 \
        $PRESERVED_X $PRESERVED_Y \
        $PRESERVED_W $window_new_h
    prorate_other_windows \
        $window_x $window_y $PRESERVED_W $window_new_h "h"
    ;;
  --increment-left)
    window_new_x=$(($adjusted_window_x - $(($RESIZE_STEP * 2))))
    window_new_w=$(($window_w + $(($RESIZE_STEP * 2))))
    put_window_by_id "$window_id" 1 \
        $window_new_x $PRESERVED_Y \
        $window_new_w $PRESERVED_H
    prorate_other_windows \
        $window_new_x $window_y $window_new_w $window_h "w"
    ;;
  --increment-right)
    window_new_w=$(($window_w + $(($RESIZE_STEP * 2))))
    put_window_by_id "$window_id" 1 \
        $PRESERVED_X $PRESERVED_Y \
        $window_new_w $PRESERVED_H
    prorate_other_windows \
        $window_x $window_y $window_new_w $window_h "w"
    ;;
  *)
    echo "Unrecognized option: $1"
    exit 1
  esac
  shift
done
