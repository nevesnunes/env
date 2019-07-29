max_width=0
max_height=0
for i in "$@"; do
  i_width=$(identify -format "%w" "$i")
  i_height=$(identify -format "%h" "$i")
  [[ $i_width -gt $max_width ]] && max_width=$i_width
  [[ $i_height -gt $max_height ]] && max_height=$i_height
done

convert -density 150 "$@" -background white -gravity center -extent "${max_width}x${max_height}" output.pdf
