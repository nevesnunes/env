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

# Debug terminal colors in tmux
tmux new-session 'echo $TERM > /tmp/a && tput colors >> /tmp/a' && cat /tmp/a && rm /tmp/a

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

# Grep UTF-16 file
tail -f file.txt | \
    LC_CTYPE=C awk '{ gsub("[^[:print:]]", ""); if($0 ~ /Result/) print; }'

# Capture output of a program that behaves differently when its stdout is not a tty
tail -c +1 -f file.txt | \
    script -qc 'iconv -f UTF-16LE -t UTF-8' /dev/null | grep Result

# sql inner join
join -t , -1 2 -2 1 <(sort -t , -k 2 enrollments.csv) <(sort -t , -k 1 courses.csv)

# Processes using swap
for file in /proc/*/status ; do awk '/VmSwap|Name/{printf $2 " " $3}END{ print ""}' $file; done | sort -k 2 -n -r | less

# rsync delta transfer
rsync -Pa --checksum --inplace --no-whole-file

# HTTP/2 web server with automatic HTTPS
caddy -conf ~/config/Caddyfile

# edit file in differnet branch
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
