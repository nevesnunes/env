# Parameters, Expansions
# Reference: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html#tag_18_06

# Debug

set -vx

i=0; while caller $i; do ((i++)); done

# Profiling
# Reference: https://stackoverflow.com/a/20855353/8020917

exec 3>&2 2> >( tee /tmp/sample-$$.log |
  sed -u 's/^.*$/now/' |
  date -f - +%s.%N >/tmp/sample-$$.tim)

paste <(
    while read tim ;do
    [ -z "$last" ] && last=${tim//.} && first=${tim//.}
    crt=000000000$((${tim//.}-10#0$last))
    ctot=000000000$((${tim//.}-10#0$first))
    printf "%12.9f %12.9f\n" \
      ${crt:0:${#crt}-9}.${crt:${#crt}-9} \
      ${ctot:0:${#ctot}-9}.${ctot:${#ctot}-9}
    last=${tim//.}
  done < sample-time.24804.tim
) sample-time.24804.log

# Pipe buffer
# Reference: http://www.gibney.de/the_output_of_linux_pipes_can_be_indeter

# Sum times skipping builtins

seq 2 | \
  xargs -i env TIME="%e" time sh -c 'sleep 2' 2>&1 | \
  awk '{s+=$1} END {printf "%.0f", s}'

# Create directories without permissions race condition
# Reference: man 2 umask
# Yak shave: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=304556

log_dir=
old_umask=$(umask)
umask 077
mkdir -p "$log_dir"
umask "$old_umask"
chmod 700 "$log_dir"

# Null byte terminated

basename -z
find . -print0
grep -Z
sed -z
sort -z
uniq -z

# Convert all '.png' files in the current directory to '.jpg' with the same name
basename -azs .jpg ./*.jpg | \
  xargs -0 -I{} convert {}.png {}.jpg

# Repackage all '.mp4' files in the current directory as '.mkv'
basename -azs .mp4 ./*.mp4 | \
  xargs -0 -I{} ffmpeg -i {}.mp4 \
    -acodec copy \
    -vcodec copy \
    {}.mkv

# Bracketed paste
# https://superuser.com/questions/1532688/pasting-required-text-into-terminal-emulator-results-in-200required-text

# add command to history
read -r target_file
cmd="foo $target_file"
eval "$cmd"
if pgrep bash >/dev/null; then
  history -s "$cmd"
else
  print -s "$cmd"
fi

# Manuals
man ascii
man operator
man hier
man 7 signal
man 3 errno
errno -l
