#!/usr/bin/env sh

{ pgrep zenity | xargs -I{} cat /proc/{}/cmdline | xargs -0 echo | grep -q 'zenity --calendar'; } || zenity --calendar
