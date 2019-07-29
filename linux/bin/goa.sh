#!/usr/bin/env bash

# HACK: Fixes Gmail timeout in Evolution

output=$( (/usr/libexec/goa-daemon --replace >&2) 2>&1)
notify-send "[goa.sh] Restarting GOA..." "$output"
