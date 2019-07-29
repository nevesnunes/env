#!/usr/bin/env sh

xdotool getactivewindow windowminimize
env SDL_AUDIODRIVER=alsa PULSE_LATENCY_MSEC=150 "$@"
