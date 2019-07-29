#!/usr/bin/env bash

function apply_grid_layout {
  # Extract tile info
  digit='[1-9]'
  chars=($(echo "$*" | sed -e 's/\(.\)/\1\n/g'))
  tile_in_grid_x_counts=()
  declare -i tile_in_grid_split_count=1
  declare -i tile_x_current_count=0
  for i in "${chars[@]}"; do
    if [[ "$i" =~ $digit ]]; then
      tile_x_current_count+=1
    elif [[ "$i" =~ , ]]; then
      tile_in_grid_split_count+=1
      tile_in_grid_x_counts+=($tile_x_current_count)
      tile_x_current_count=0
    fi
  done
  tile_in_grid_x_counts+=($tile_x_current_count)

  tile_info=()
  declare -i tile_split_index=0
  declare -i tile_x_index=0
  declare -i tile_in_grid_x_counts_index=0
  for (( i=0; i<"${#chars[@]}"; i++ )); do
    char="${chars[$i]}"
    if [[ "$char" =~ $digit ]]; then
      for (( j=0; j<$char; j++ )); do
        tile_info+=( \
            "$(($tile_x_index + 1))" \
            "${tile_in_grid_x_counts[$tile_in_grid_x_counts_index]}" \
            "$(($(($j + 1)) + $(($char * $tile_split_index))))" \
            "$(($char * $tile_in_grid_split_count))" \
        )
      done
      tile_x_index+=1
    elif [[ "$char" =~ "," ]]; then
      tile_split_index+=1
      tile_in_grid_x_counts_index+=1
      tile_x_index=0
    fi
  done
  printf '%s %s %s %s\n' "${tile_info[@]}"

  # Reverse ids so that the last focused windows are
  # the first to be tiled
  ids=($(xdotool search --desktop "$desktop" --name ""))
  ordered_ids=("$focus_id")
  for (( i=${#ids[@]}-1; i>=0; i-- )); do
    if [[ "${ids[$i]}" != "$focus_id" ]]; then
      ordered_ids+=("${ids[$i]}")
    fi
  done

  # Tile each window
  declare -i tile_info_index=0
  for i in "${ordered_ids[@]}"; do
    xsize.sh --id "$i" --tile-in-grid \
      "${tile_info[$tile_info_index]}" \
      "${tile_info[$(($tile_info_index + 1))]}" \
      "${tile_info[$(($tile_info_index + 2))]}" \
      "${tile_info[$(($tile_info_index + 3))]}"
    if [[ "${#tile_info[@]}" -gt $(($tile_info_index + 4)) ]]; then
      tile_info_index+=4
    fi
  done
}

desktop=$(xdotool get_desktop)

# Remember focused window, since layout updates can change it
focus_id=$(xdotool getwindowfocus)

while [ "$1" != "" ]; do
  case $1 in
  Split-Horizontal)
    apply_grid_layout "1,11"
    ;;
  Split)
    apply_grid_layout "12"
    ;;
  Digits)
    shift
    apply_grid_layout "$*"
    ;;
  *)
    echo "Unrecognized option: $1"
    exit 1
  esac
  shift
done

xdotool windowactivate --sync "$focus_id"
xdotool windowraise "$focus_id"
