#!/usr/usr/bin/env bash

LINK="$(xclip -o)"
exec mpv "${LINK}"
