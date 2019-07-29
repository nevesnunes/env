#!/usr/bin/env bash
a=2
wmctrl -lx | awk -v a="$a" '$2 == "a" {print $1" "$3}'
