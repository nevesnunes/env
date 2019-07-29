#!/usr/bin/env bash

unset TERMCAP
re_env=$(env | \
	cut -d= -f1 | \
	tr -dc '_[:alnum:][:space:]' | \
	tr \\n '|')
re_dot_smthg='\.[^ ]+'
re_autovars='[%*+<?^@][^ ]'
re_misc='GNUMAKEFLAGS|MAKE([^ ]+)?|MFLAGS|SUFFIXES|-\*-command-variables-\*-'

make -rR -pk -q "$@" \
    | grep -vE "^(${re_env}#|$re_dot_smthg|$re_autovars|$re_misc) " \
    | cat -s
