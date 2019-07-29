#!/usr/bin/env bash

sox _ -c2 -r 44100 -n spectrogram

# Debug

sox ... -V

# Windows

sox -n -t waveaudio -r 48000 synth pinknoise band -n 2500 6000 reverb 2 vol 0.5
sox -m \
    |sox -n -t waveaudio -r 50000 synth trapezium mix F2 band -n 8192 12000 vol 0.1 \
    |sox -n -t waveaudio -r 50000 synth trapezium mix G2 band -n 8192 12000 pitch 50 vol 0.1 \
    |sox -n -t waveaudio -r 50000 synth pinknoise band -n 2500 6000 reverb 2 vol 0.5
