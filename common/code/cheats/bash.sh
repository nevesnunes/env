# Parameters, Expansions
# - http://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html#tag_18_06

# Completion Bugs
# - http://www.oilshell.org/blog/2020/01/history-and-completion.html

# Debug

set -vx

i=0; while caller $i; do ((i++)); done

# Profiling
# - [profiling \- How to profile a bash shell script slow startup? \- Stack Overflow](https://stackoverflow.com/a/20855353/8020917)

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
# - http://www.gibney.de/the_output_of_linux_pipes_can_be_indeter

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
# - https://superuser.com/questions/1532688/pasting-required-text-into-terminal-emulator-results-in-200required-text

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

# Trace with specific shell options
env \
    SHELLOPTS="$(echo xtrace${SHELLOPTS:+:${SHELLOPTS}} | \
    gawk '
        BEGIN {
            buf = ""
            RS = ":"
        }
        /emacs|histexpand|history|monitor/ {
            next
        } 
        NF {
            gsub(/[\s\r\n]*/,"",$0);
            buf = buf ? buf":"$0 : $0
        }
        END {
            print buf
        }
    ')" \
    BASH_XTRACEFD=7 \
    PS4='[${BASH_SOURCE:-$BASH_EXECUTION_STRING}:$LINENO]> ' \
    foo.sh \
    7>/1

# diff files filtered by timestamp

diff -aurwq dir_1/ dir_2/ | \
  grep '^Files' | \
  xargs -i sh -c '
    [ "$2" -ot "$4" ] && printf "%s\n" "$*"
  ' _ {}
# ||
diff -aurwq dir_1/ dir_2/ | \
  grep '^Files' | \
  xargs -i sh -c '
    source_ts=$(date +"%s%N" -d "$(stat --printf="%y\n" "$2")")
    target_ts=$(date +"%s%N" -d "$(stat --printf="%y\n" "$4")")
    [ "$source_ts" -lt "$target_ts" ] && printf "%s\n" "$*"
  ' _ {}

# xargs behaviour with input
printf '%s\n' '1 2' | xargs -L1 sh -c 'echo $1' _  
# 1                                                    
printf '%s\n' '1 2' | xargs -n1 sh -c 'echo $1' _  
# 1                                                    
# 2                                                    
printf '%s\n' '1 2' | xargs -i sh -c 'echo $1' _ {}
# 1 2                                                  
printf '%s\n' '1 2' | xargs -I{} sh -c 'echo $1' _ {}
# 1 2                                                  

# xargs behaviour with empty input
printf '%s\n' '' | xargs -L1 sh -c 'echo =$1' _  
# ={}
printf '%s\n' '' | xargs -n1 sh -c 'echo =$1' _  
# ={}
printf '%s\n' '' | xargs -i sh -c 'echo =$1' _ {}
#
printf '%s\n' '' | xargs -I{} sh -c 'echo =$1' _ {}
#

# xargs behaviour without input
true | xargs -L1 sh -c 'echo 0' _
# 0
true | xargs -n1 sh -c 'echo 0' _
# 0
true | xargs -i sh -c 'echo 0' _ {}
#

# sort files with encoding different from locale

echo '
./foo
./bar
' | xargs -i diff -uw dir_1/{} dir_2/{} | cat | vim -

echo '
./foo
./bar
' | xargs -i bash -c '
    export LC_ALL=C
    diff -uw \
        <(dos2unix < dir_1/"$1" | sort) \
        <(dos2unix < dir_2/"$1" | sort)' _ {} | \
    cat | \
    vim -

echo '
./foo
./bar
' | xargs -i bash -c '
    f1=dir_1/"$1"
    f2=dir_2/"$1"
    f1_mime=$(file --brief --mime-encoding "$f1")
    f2_mime=$(file --brief --mime-encoding "$f2")
    diff -uw \
        <(iconv -f "$f1_mime" -t utf-8 "$f1" | dos2unix | sort) \
        <(iconv -f "$f2_mime" -t utf-8 "$f2" | dos2unix | sort)' _ {} | \
    cat | \
    vim -

echo '
./foo
./bar
' | xargs -i bash -c '
    f1=dir_1/"$1"
    f2=dir_2/"$1"
    f1_mime=$(file --brief --mime-encoding "$f1")
    f2_mime=$(file --brief --mime-encoding "$f2")
    diff -uw \
        <(if echo "$f1_mime" | \
            grep -v "ascii\|binary\|utf-8"; then \
            iconv -f "$f1_mime" -t utf-8 "$f1"; else \
            cat "$f1"; fi | dos2unix | sort) \
        <(if echo "$f2_mime" | \
            grep -v "ascii\|binary\|utf-8"; then \
            iconv -f "$f2_mime" -t utf-8 "$f2"; else \
            cat "$f2"; fi | dos2unix | sort)' _ {} | \
    cat | \
    vim -

# preview input to pipe
a=$(printf '%s\n' 1 2 3) && printf '%s' "$a" >&2 && read -r && printf '%s\n' "$a" | xargs -i ls {};

# cannot declare a function with same name as alias
# e.g.
# bash: foo.sh: line 18: syntax error near unexpected token `('
# bash: foo.sh: line 18: `ssh() {'
unalias ssh
eval 'ssh() { :; }'

# jail
# - https://github.com/w181496/Web-CTF-Cheatsheet#%E7%A9%BA%E7%99%BD%E7%B9%9E%E9%81%8E
cat$IFS$*flag
cat</etc/passwd
{cat,/etc/passwd}
X=$'cat\x20/etc/passwd'&&$X
IFS=,;`cat<<<uname,-a`


