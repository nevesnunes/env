#!/usr/bin/env bash

err="usage: $FUNCNAME [object]"
test $# -ne 1 && echo "$err" && return 1

IFS=$'\n' manpgs=( $(apropos "$1" | grep ^"$1") )
select line in "${manpgs[@]}"; do
    n=${line%%) *}; n=${n#* (}
    man "${n}" "${line%% *}"
done
