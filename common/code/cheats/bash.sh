# Parameters, Expansions

# http://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html#tag_18_06

# Debug

i=0; while caller $i; do ((i++)); done

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

# Profiling

# https://stackoverflow.com/a/20855353/8020917

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

# http://www.gibney.de/the_output_of_linux_pipes_can_be_indeter
