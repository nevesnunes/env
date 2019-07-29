#!/usr/bin/env bash

APP=`basename "$0"`

die() {
    echo $APP: "$@" >&2
    exit 1
}

usage() {
    echo 'usage: '$APP' WORKSPACE CMD [ARG]...'
    echo
    echo 'WORKSPACE is the zero-based index of the workspace'
    exit 1
}

# check wmctrl is available
[[ -x `which wmctrl` ]] || die "please install wmctrl"

# we should have at least 2 args
[[ -n "$2" ]] || usage

# check workspace
WS=$1
[[ $(( 0 + $WS )) -gt 0 || "$WS" == "0" ]] || usage
shift

# launch program
"$@" &
CPID=$!

# look for the window every 0.1 seconds for 10 seconds
for (( A = 0; A < 100; A++ )); do
    sleep 0.1

    # has child process terminated?
    [[ -d /proc/$CPID ]] || break

    # try to find process's window ID
    WID=`wmctrl -lp | \
        egrep '^0x[0-9a-f]+ +[-0-9]+ +'$CPID' ' | \
        awk '{print $1}'`
    if [[ -n "$WID" ]]; then

        # move the window
        wmctrl -ir $WID -t $WS
        break

    fi
done

# failed?
[[ $A -eq 100 ]] && die "couldn't find application's window..."
