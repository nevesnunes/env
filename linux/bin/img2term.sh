#!/usr/bin/env bash
#
# z3bra -- 2014-01-21
#
# Draws the image depending on the terminal size (width AND height),
# and put the cursor after the image (exactly 2 lines after).

get_w3m_img_path() {
    if [[ -x "$w3m_img_path" ]]; then
        return
    elif [[ -x "/usr/lib/w3m/w3mimgdisplay" ]]; then
        w3m_img_path="/usr/lib/w3m/w3mimgdisplay"
    elif [[ -x "/usr/libexec/w3m/w3mimgdisplay" ]]; then
        w3m_img_path="/usr/libexec/w3m/w3mimgdisplay"
    elif [[ -x "/usr/lib64/w3m/w3mimgdisplay" ]]; then
        w3m_img_path="/usr/lib64/w3m/w3mimgdisplay"
    elif [[ -x  "/usr/libexec64/w3m/w3mimgdisplay" ]]; then
        w3m_img_path="/usr/libexec64/w3m/w3mimgdisplay"
    fi
}

get_term_size() {
    # This functions gets the current window size in
    # pixels.
    #
    # We first try to use the escape sequence "\044[14t"
    # to get the terminal window size in pixels. If this
    # fails we then fallback to using "xdotool" or other
    # programs.

    # Tmux has a special way of reading escape sequences
    # so we have to use a slightly different sequence to
    # get the terminal size.
    if [[ -n "$TMUX" ]]; then
        printf "%b" "\033Ptmux;\033\033[14t\033\033[c\033\\"
        read_flags=(-d c)
    else
        printf "%b" "\033[14t\033[c"
        read_flags=(-d c)
    fi

    # The escape codes above print the desired output as
    # user input so we have to use read to store the out
    # -put as a variable.
    IFS=";" read -s -t 1 "${read_flags[@]}" -r -a term_size

    # Split the string into height/width.
    term_height="${term_size[1]}"
    term_width="${term_size[2]/t*}"

    # Get terminal width/height if \033[14t is unsupported.
    if [[ -z "$term_width" && "$image_program" == "w3m" ]]; then
        if type -p xdotool >/dev/null 2>&1; then
            current_window="$(xdotool getactivewindow)"
            source <(xdotool getwindowgeometry --shell "$current_window")
            term_height="$HEIGHT"
            term_width="$WIDTH"

        elif type -p xwininfo >/dev/null 2>&1; then
            # Get the focused window's ID.
            if type -p xdpyinfo >/dev/null 2>&1; then
                current_window="$(xdpyinfo | grep -E -o "focus:.*0x[0-9a-f]+")"
                current_window="${current_window/*window }"
            elif type -p xprop >/dev/null 2>&1; then
                current_window="$(xprop -root | awk '/_NET_ACTIVE_WINDOW\(WINDOW\)/{print $NF}')"
            fi

            # If the ID was found get the window size.
            if [[ "$current_window" ]]; then
                term_size="$(xwininfo -id "$current_window" | awk -F ': ' '/Width|Height/ {printf $2 " "}')"
                term_width="${term_size/ *}"
                term_height="${term_size/${term_width}}"
            else
                term_width=0
            fi
        else
            term_width=0
        fi
    fi

    # If the terminal size was found correctly.
    if [[ "$term_width" ]] && ((term_width >= 1)); then
        clear
        zws="​ "
    fi
}

get_image_size() {
    # This functions determines the size to make
    # the thumbnail image.

    # Get terminal lines and columns.
    term_blocks="$(stty size)"
    columns="${term_blocks/* }"
    lines="${term_blocks/ *}"

    # Calculate font size.
    font_width="$((term_width / columns))"
    font_height="$((term_height / lines))"

    case "$image_size" in
        "auto")
            image_size="$((columns * font_width / 2))"
            term_height="$((term_height - term_height / 4))"

            ((term_height < image_size)) && \
                image_size="$term_height"
        ;;

        *"%")
            percent="${image_size/\%}"
            image_size="$((percent * term_width / 100))"

            (((percent * term_height / 50) < image_size)) && \
                image_size="$((percent * term_height / 100))"
        ;;

        "none")
            # Get image size so that we can do a better crop.
            size="$(identify -format "%w %h" "$image")"
            width="${size%% *}"
            height="${size##* }"
            crop_mode="none"
        ;;

        *) image_size="${image_size/px}" ;;
    esac

    width="${width:-$image_size}"
    height="${height:-$image_size}"

    text_padding="$((width / font_width + gap + xoffset/font_width))"
}

make_thumbnail() {
    # Name the thumbnail using variables so we can
    # use it later.
    image_name="$crop_mode-$crop_offset-$width-$height"

    # Check to see if the image has a file extension,
    # if it doesn't then add one.
    case "${image##*/}" in
        *"."*) image_name="${image_name}-${image##*/}" ;;
        *) image_name="${image_name}-${image##*/}.jpg" ;;
    esac

    # Create the thumbnail dir if it doesn't exist.
    mkdir -p "$thumbnail_dir"

    # Check to see if the thumbnail exists before we do any cropping.
    if [[ ! -f "$thumbnail_dir/$image_name" ]]; then
        # Get image size so that we can do a better crop.
        if [[ -z "$size" ]]; then
            size="$(identify -format "%w %h" "$image")"
            og_width="${size%% *}"
            og_height="${size##* }"

            # This checks to see if height is greater than width
            # so we can do a better crop of portrait images.
            size="$og_height"
            ((og_height > og_width)) && size="$og_width"
        fi

        case "$crop_mode" in
            "fit")
                c="$(convert "$image" \
                    -colorspace srgb \
                    -format "%[pixel:p{0,0}]" info:)"

                convert \
                    "$image" \
                    -trim +repage \
                    -gravity south \
                    -background "$c" \
                    -extent "$size"x"$size" \
                    -scale "$width"x"$height" \
                    "$thumbnail_dir/$image_name"
            ;;

            "fill")
                convert \
                    "$image" \
                    -trim +repage \
                    -scale "$width"x"$height"^ \
                    -extent "$width"x"$height" \
                    "$thumbnail_dir/$image_name"
            ;;

            "none") cp "$image" "$thumbnail_dir/$image_name" ;;
            *)
                convert \
                    "$image" \
                    -gravity "$crop_offset" \
                    -crop "$size"x"$size"+0+0 \
                    -quality 95 \
                    -scale "$width"x"$height" \
                    "$thumbnail_dir/$image_name"
            ;;
        esac
    fi

    # The final image.
    image="$thumbnail_dir/$image_name"
}

display_image() {
  # Add a tiny delay to fix issues with images not
  # appearing in specific terminal emulators.
  sleep 0.05
  printf "%b\n" "0;1;$xoffset;$yoffset;$width;$height;;;;;$image\n4;\n3;" |\
  "$w3m_img_path" -bg "$background_color" >/dev/null & 2>&1 || to_off "Images: w3m-img failed to display the image."
}

test -z "$1" && exit

W3MIMGDISPLAY="/usr/lib/w3m/w3mimgdisplay"
FILENAME=$1
FONTH=14 # Size of one terminal row
FONTW=8  # Size of one terminal column
COLUMNS=`tput cols`
LINES=`tput lines`

read width height <<< `echo -e "5;$FILENAME" | $W3MIMGDISPLAY`

max_width=$(($FONTW * $COLUMNS))
max_height=$(($FONTH * $(($LINES - 2)))) # substract one line for prompt

if test $width -gt $max_width; then
height=$(($height * $max_width / $width))
width=$max_width
fi
if test $height -gt $max_height; then
width=$(($width * $max_height / $height))
height=$max_height
fi

w3m_command="0;1;0;0;$width;$height;;;;;$FILENAME\n4;\n3;"

tput cup $(($height/$FONTH)) 0
echo -e $w3m_command|$W3MIMGDISPLAY
