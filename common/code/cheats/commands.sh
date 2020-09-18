# Suspend (systemctl) [sleep]
systemctl -i suspend

# Reboot (systemctl) [restart]
systemctl -i reboot

# Power Off (systemctl) [shutdown]
systemctl -i poweroff

# Kernel Messages (dmesg)
watch -n 5 dmesg | tail -n 15

# Network Statistics (netstat)
watch -n 5 "netstat -at | grep -v LISTEN"

# System Journal (journalctl)
journalctl -f

# List zsh commands (alias)
alias | cut -f1 -d= ; hash -f; hash -v | cut -f 1 -d= | sort

# List shell frequent commands (history)
history | awk '{print $2}' | sort | uniq -c | sort -nr | head

# Monitor Disk Input/Output (iotop) [read, write]
sudo iotop

# Monitor Cummulative Disk Input/Output (pidstat) [read, write]
pidstat -dl 20

# System recent journal (journalctl)
journalctl --since="30 minutes ago"

# Show IP address info (ip)
ip addr show

# SELinux audit log
sudo sealert -a /var/log/audit/audit.log

# Power Off monitor (dkms)
xset dpms force off

# Print key names (xkbprint)
xkbprint -label name $DISPLAY

# Audio Mixer (alsamixer) [music, sound, volume, level]
alsamixer

# Process Monitor (htop) [memory, input/output, resources, kill]
htop

# Find all logs changed within 5 minutes
find /var/log -mmin -5

# Weather (curl) [wttr.in, wego]
curl wttr.in 2>/dev/null | head -n7; read -n 1

# Retrieve page with cookies
curl -O -J -L -b cookies.txt _

# POST multipart file from stdin
curl http://foo/bar -F 'file=@-' < _

# PUT file from stdin
curl http://foo/bar --upload-file - < _

# Display keyboard layout (gkbd-keyboard-display) [show]
gkbd-keyboard-display -l "$(~/bin/blocks/keymap | awk '{print $2}')"

# List Built-in Kernel Modules
cat /lib/modules/"$(uname -r)"/modules.builtin

# Fuzzy search manual pages 7 `Miscellaneous` (apropos)
apropos -s 7 "" | fzf | cut -d"(" -f1 | xargs man

# Regenerate tags for javascript code (jsctags)
find . -type f \
  -iregex ".*\.js$" -not -path "./node_modules/*" \
  -exec jsctags {} -f \; | \
  sed "/^$/d" | \
  sort > tags

# Gracefully close/kill windows (wmctrl)
(wmctrl -l | \
  grep -v -E "(xterm|scratchpad)" | \
  cut -d" " -f1 | \
  xargs -d'\n' -I{} -n1 -r wmctrl -i -c {}); \
  killall tmux; \
  uf.sh

# Git fuzzy show commit log (fzf)
git show $(git log --pretty=oneline --abbrev-commit | fzf | cut -d" " -f1)

# Git fuzzy interactive commit log (fzf)
git log --date=short --format="%C(green)%C(bold)%cd %C(auto)%h%d %s (%an)" --graph --color=always | \
  fzf --ansi --no-sort --reverse --multi --preview 'grep -o "[a-f0-9]\{7,\}" <<< {} | xargs git show --color=always | head -'$LINES | grep -o "[a-f0-9]\{7,\}" | grep -o "[a-f0-9]\{7,\}" <<< {} | \
  xargs git show --color=always | \
  $PAGER

# Git remove added files that were later ignored
git rm -r --cached . && \
  git add . && \
  git clean -x -n

# Run new display in a window (xephyr)
Xephyr -ac -screen 800x600 -br -reset -terminate 2> /dev/null :3 &

# Show backtrace of all active CPUs (sysrq-trigger) [call list dump stack kworker]
sudo su -c 'echo l > /proc/sysrq-trigger'; dmesg

# Record backtrace of all active CPUs (perf) [call list dump stack kworker]
sudo perf record -g -a sleep 10; sudo perf report

# Generate noise
play -n synth brownnoise synth pinknoise vol 0.9

# List IP address in network segment [ethernet, switch]
arp -a

# Debug suspend, logged in /var/log/pm-suspend.log
PM_DEBUG=true pm-suspend

# Wine prefix older then Windows XP
env WINEARCH=win32 WINEPREFIX=$HOME/wine-win32 winecfg

# Wine debug
env WINEDEBUG=+all winedbg

# Qt debug
export QT_DEBUG_PLUGINS=1

# Dynamic library debug
export LD_DEBUG=libs

# strace verbose
strace -f -s 9999 -v

# Debug non-printable chars
cat -vet

# Replace line in file
lineno=$(grep -n "# foo" /etc/foo.conf | grep -Eo '^[^:]+')
sed -i "$(($lineno+1))foo" /etc/foo.conf

# Encode, Compress, Increase Contrast of JPG
# References:
# https://developers.google.com/speed/docs/insights/OptimizeImages
# https://www.imagemagick.org/Usage/color_mods/#levels
convert image.jpg -sampling-factor 4:2:0 -strip -quality 85 -interlace JPEG -colorspace RGB -level '10%,85%,1.5' image_converted.jpg

# Repair VM
vmware-vdiskmanager -R _
VBoxManage internalcommands repairhd _ -format VDI

# Split flac
shnsplit -f file.cue -t '%n. %t' -o flac file.flac
# ||
cuebreakpoints file.cue | shnsplit -t '%n. %t' -o flac file.flac

# Add metadata tags from cue to audio files
env IFS=$'\n' cuetag.sh foo.cue *.flac

# Fix WAV
sox --ignore-length corrupted.wav fixed.wav
soxi file.wav
sox normal.wav -b 16 -r 16000 -c 1 specific.wav

# Number of possible file handlers open at once
cat /proc/sys/fs/file-max

# Remove images from mp3
mkdir -p ./a && for i in *.mp3; do ffmpeg -i "$i" -c:a copy -vn "a/$i"; done && mv a/*.mp3 . && rmdir a

# Calculate accuraterip checksums
for ((i=1; i<99; i++)); do ~/opt/accuraterip-checksum/accuraterip-checksum $(printf "%02d" "$i")*.flac $i 99 || break; done

# Iterate over systemd services
find /etc/systemd/system/ -iname 'abrt*' | sed 's/.*\///g' | xargs -d'\n' -I{} systemctl stop {}

# Suspend process
kill -s SIGSTOP <PID>
kill -s SIGCONT <PID>

# cvs
cvsroot=$(realpath foo/) && \
  find "$cvsroot" \( -iname '\#cvs.lock' -o -iname '\#cvs.wfl*' -o -iname '\#cvs.rfl*' \) -print0 | xargs -0 -I{} rm -rf {} && \
  cvs -d "$cvsroot" co bar

# Average images
convert image1 image2 -evaluate-sequence mean result

# Detect interactive user
last -f /var/log/wtmp
last -f /var/run/utmp
inotify on utmp

# Toggle sound, mute
amixer -q -D pulse sset Master toggle
amixer set Master toggle

# Function body to string
type foo | tr '\n' '\f' | sed 's/[^{]*{\([^}]*\)}\s*$/\1/' | tr '\f' '\n'

# View man page as html
groff -mandoc -Thtml foo | w3m -T text/html

# Show first entry for each subsystem
awk '{ if (!($2 in seen)) print $0; seen[$2] = 1; }'

# Show last entry for each subsystem (won't preserve input order)
awk '{ seen[$2] = $0; } END { for (k in seen) print seen[k]; }'

# Parallel processing
xargs -P8
# Validation:
seq 1 20 | xargs -P0 -i bash -c 'sleep 0.2; echo -- "$1"' _ {}

# Grep UTF-16 file
tail -f file.txt | \
  LC_CTYPE=C awk '{ gsub("[^[:print:]]", ""); if($0 ~ /Result/) print; }'

# Capture output of a program that behaves differently when its stdout is not a tty
tail -c +1 -f file.txt | \
  script -qc 'iconv -f UTF-16LE -t UTF-8' /dev/null | grep Result

# sql inner join
join -t , -1 2 -2 1 <(sort -t , -k 2 enrollments.csv) <(sort -t , -k 1 courses.csv)

# Processes using swap
for file in /proc/*/status; do awk '/Name/{printf "%24s", $2} /Tgid|VmSwap/{printf " %8s %s", $2, $3} END{print ""}' $file; done | grep kB | sort -k 3 -n

# delta transfer
rsync -Pa --checksum --inplace --no-whole-file

# delete extraneous files
rsync -rv --delete --existing --ignore-existing --ignore-errors foo/ bar/

# HTTP/2 web server with automatic HTTPS
caddy -conf ~/config/Caddyfile

# edit file in different branch
git show branch_name:/path/to/file.pl | vim - -c 'set syntax=perl'

# input on stdin for commands taking input on file
./foo --file=/proc/self/fd/0
./foo --file=/dev/stdin
mkfifo pipe && ./foo --file=pipe

# monitoring the progress of data through a pipeline
pv -cN source < foo | bzcat | pv -cN bzcat

# find duplicate albums
\ls -1 . | \
  awk '{gsub(/\[.*\]|\(.*\)|^[:space:]*|[:space:]*$/, "", $0); printf("%s%c", $0, 0)}' | \
  xargs -0 -I{} find foo/ -iname '*'{}'*'

# remove all exif metadata
exiftool image.jpg -all=

# Audio downmix surround 5.1 channels to stereo
mpv --ad-lavc-downmix=no --audio-channels=stereo

# HTTPS, SSL strip
mitmproxy -s ~/opt/mitmproxy/examples/complex/sslstrip.py --set ssl_insecure=true

# strings with filename and offset
strings --print-file-name --radix=x * | vim -

# fix labels outside svg
for i in *.svg; do inkscape -f "$i" \
  --verb=FitCanvasToDrawing \
  --verb=FileSave \
  --verb=FileQuit \
  ; done

# sorted disk usage summary
du -hs * | sort -h

# enable swap
sudo fstab -l | grep -i swap
sudo swapon -a /dev/mapper/fedora_mnu-swap

# shell - skip writing history
export HISTFILE=
kill -9 $$

# awk - first instance with common prefix
awk '{
dir = substr($0, 1, match($0, /\/[^\/]*$/))
if (!seen[dir]) {
  print
  seen[dir]++
}
}'

# generate qr code
qrencode -t ASCII 'foo' | sed 's/#/█/g'

# call library function
\vim -u NONE -c 'redir>>/dev/stdout | echo libcall ("'"$(ldd "$(command -pv vim)" | awk '/libc.so/{print $1; exit}')"'", "getenv", "HOME") | q'

# configure webcam
v4l2ucp

# remove duplicate files
fdupes -r --delete .

# dd monitoring with progress / timer / status indicator
dd if=foo of=/dev/sdb bs=4M status=progress
# ||
dd if=foo | pv -s 2.8G | dd of=/dev/sdb bs=4M
# ||
pgrep '^dd$' | xargs -i kill -USR1 {}
# || https://blog.sleeplessbeastie.eu/2015/01/23/how-to-check-the-progress-of-dd-using-proc-filesystem/
sudo su -c "pgrep '^dd$' | xargs -i cat /proc/{}/io | awk '/wchar/ {print \$2}'"

# hardware info
dmidecode
# || motherboard
cat /sys/devices/virtual/dmi/id/board_*

# image format / resolution
# https://imagemagick.org/script/identify.php
magick identify foo.png

# auto-detect changes in acpi devices
# https://askubuntu.com/questions/23508/how-to-automatically-change-volume-level-when-un-plugging-headphones
acpi_listen > /tmp/foo
echo '/tmp/foo' | entr ./bar

# backlight
# Requires: disabled settings daemon color plugin
# Reference: [Sometimes when I open a window \(especially chromium\) brightness controller resets brightness settings to default \(not on app ui\) · Issue \#102 · LordAmit/Brightness · GitHub](https://github.com/LordAmit/Brightness/issues/102)
xrandr | awk '/ connected /{print $1}' | xargs -i xrandr --output {} --brightness .9
gdbus call --session --dest org.gnome.SettingsDaemon.Power --object-path /org/gnome/SettingsDaemon/Power --method org.freedesktop.DBus.Properties.Set org.gnome.SettingsDaemon.Power.Screen Brightness "<15>"
gdbus call --session --dest org.gnome.SettingsDaemon.Power --object-path /org/gnome/SettingsDaemon/Power --method org.freedesktop.DBus.Properties.Get org.gnome.SettingsDaemon.Power.Screen Brightness

# vectorize raster image (autotrace)
convert -channel RGB -compress None -enhance -contrast +dither -colors 16 -depth 4 input.png bmp:- | potrace -s - -o output.svg

# List fonts and code points for matched fontconfig rule
#
# `fc-match` options:
# - ldd /usr/bin/fc-match
# - strings /lib64/libfontconfig.so.1
#
# `strace` patterns for `unipicker --command 'rofi -dmenu'`:
# - removed reads from cached font entries
#    - :%s/openat.*fontconfig.*\.cache.*\n.*fstat.*\n.*fstatfs.*\n.*mmap.*//g
# - got actual fonts loaded
# [pid 1608961] access("/home/fn/.local/share/fonts/Meslo LG DZ v1.2.1/MesloLGMDZ-Regular.ttf", R_OK) = 0
# [pid 1608961] openat(AT_FDCWD, "/home/fn/.local/share/fonts/Meslo LG DZ v1.2.1/MesloLGMDZ-Regular.ttf", O_RDONLY) = 9
# [pid 1608961] fcntl(9, F_SETFD, FD_CLOEXEC) = 0
# [pid 1608961] fstat(9, {st_mode=S_IFREG|0664, st_size=636196, ...}) = 0
# [pid 1608961] mmap(NULL, 636196, PROT_READ, MAP_PRIVATE, 9, 0) = 0x7f170b559000
# [pid 1608961] close(9)                  = 0
# ...
# [pid 1608961] access("/usr/share/fonts/google-noto-emoji/NotoColorEmoji.ttf", R_OK) = 0
# [pid 1608961] openat(AT_FDCWD, "/usr/share/fonts/google-noto-emoji/NotoColorEmoji.ttf", O_RDONLY) = 9
# [pid 1608961] fcntl(9, F_SETFD, FD_CLOEXEC) = 0
# [pid 1608961] fstat(9, {st_mode=S_IFREG|0644, st_size=10468356, ...}) = 0
# [pid 1608961] mmap(NULL, 10468356, PROT_READ, MAP_PRIVATE, 9, 0) = 0x7f170a0c5000
# [pid 1608961] close(9)                  = 0
# ...
# [pid 1608961] access("/usr/share/fonts/gdouros-symbola/Symbola.ttf", R_OK) = 0
# [pid 1608961] openat(AT_FDCWD, "/usr/share/fonts/gdouros-symbola/Symbola.ttf", O_RDONLY) = 9
# [pid 1608961] fcntl(9, F_SETFD, FD_CLOEXEC) = 0
# [pid 1608961] fstat(9, {st_mode=S_IFREG|0644, st_size=2440452, ...}) = 0
# [pid 1608961] mmap(NULL, 2440452, PROT_READ, MAP_PRIVATE, 9, 0) = 0x7f1709c1d000
# [pid 1608961] close(9)                  = 0
grep -Po '(?<=<family>)(.*Emoji.*)(?=</family>)' /usr/share/fontconfig/conf.avail/60-generic.conf | \
  xargs -i fc-match {} | \
  sort -u | \
  awk -F'"' '$0=$2' | \
  xargs -i fc-match --format='%{family}\n%{charset}\n' {}

# List fonts containing codepoint
# https://unix.stackexchange.com/questions/162305/find-the-best-font-for-rendering-a-codepoint/268286
fc-list ":charset=$(printf '%x' \'<0001f921>)"

# Test history on non-interactive bash shells
echo 1 | xargs -i bash -ci 'set -o history; echo $HISTFILE; history' _ {}

# lolbins - Execute command via man pager
MANPAGER='sh -c whoami' man ls

# lolbins - Read file
diff /dev/null 1
iconv 1

# hex byte sequence to binary
printf '%s' '324F8D8A20561205631920' | xxd -r -p

# match hex byte sequence in binary
xxd -p foo | tr -d '\n' | grep -aboP '2056(?=(?:[\da-fA-F]{2})*$)' | awk '{p=index($0,":"); printf("0x%x:%s\n",substr($1,0,p-1)/2, substr($1,p+1))}'

# sha checksum
cat foo.xml | openssl dgst -binary -sha1 | openssl base64
sha1sum foo.xml | cut -f1 -d\  | xxd -r -p | base64

# replace current shell
exec sudo -u $(id -u -n) -i

# match window class and name
class=
name=
xdotool search --onlyvisible --class "$class" getwindowpid %@ | xargs -i xdotool search --all --pid {} --name "$name"

# hide window from dock
# - don't search with `xprop`, since window id may not match visible window
# - don't sync on window map, it can hang when an incorrect id was picked for window unmap
# Alternatives:
# - https://stackoverflow.com/questions/19035043/setting-x11-type-property-for-xmessage
# - https://stackoverflow.com/questions/31361859/simple-window-without-titlebar
# - https://tronche.com/gui/x/xlib/window-information/XChangeProperty.html
class=
id=$(xdotool search --onlyvisible --class "$class" | xargs -i printf '0x%x' {})
xprop -id "$id" -f _NET_WM_WINDOW_TYPE 32a -set _NET_WM_WINDOW_TYPE _NET_WM_WINDOW_TYPE_NORMAL
xdotool windowunmap --sync "$id"
xdotool windowmap "$id"
# rollback
xprop -id "$id" -f _NET_WM_WINDOW_TYPE 32a -set _NET_WM_WINDOW_TYPE _NET_WM_WINDOW_TYPE_NORMAL
xdotool windowunmap --sync "$id"
xdotool windowmap "$id"

# add repos as submodules
target_root=
target=$target_root/
find . -path '*/.git/*' -iname 'config' -exec awk 'FNR == 1{ print FILENAME } /url/{print $3}' {} \; | xargs -L2 sh -c 'r=${1%\/\.git\/config} && cd "'"$target_root"'" && rm -rf "'"$target"'/$r" && git submodule add "$2" "'"$target"'/$r"' _
### sync
rsync --cvs-exclude

# send raw data
curl -H "Content-Type: text/plain" --data "foo" http://foo

# visually select images (mark with `m`)
find . -maxdepth 1 -type f -exec file --mime-type {} + \
  | awk -F: '$2 ~ /image\//{printf "%s%c", $1, 0}' \
  | xargs -0 sxiv -qto 2>/dev/null

# convert between newlines and null bytes
# e.g. paste image paths in vim:
#     map <leader>i :r !find . -maxdepth 1 -type f -exec file --mime-type {} + \| awk -F: '$2 ~ /image\//{printf "%s%c", $1, 0}' \| xargs -0 sxiv -qto 2>/dev/null <CR><CR>
#     reference: https://www.reddit.com/r/vim/comments/ic51kg/visually_select_images_and_paste_their_paths_into/
printf '%s\n' 'a 1' 'a 2' | tr '\n' '\0'
printf '%s\n' 'a 1' 'a 2' | paste -sd $'\x1e' | sed 's/\x1e/\x00/g' | xargs -0
printf '%s\x00' 'a 1' 'a 2' | tr '\0' '\n'
printf '%s\x00' 'a 1' 'a 2' | xargs -0 -n1

# mirror pages matching expression
wget -rc --accept-regex '.*http://foo.org/bar.*\..*' 'http://foo.org/bar'

# convert chm to epub
ebook-convert input.chm output.epub --dont-split-on-page-breaks --no-default-epub-cover

# image remote disk
socat openssl-listen:9999 | bunzip2 | dd of=/dev/sdc1
dd if=/dev/sdb1 | bzip2 | socat - openssl:target_host:9999


