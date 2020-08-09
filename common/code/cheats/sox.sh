#!/bin/sh

# Debug
sox ... -V

# Generate spectrogram
sox _ -c2 -r 44100 -n spectrogram

# Generate silence
sox -n -r 16000 -c 1 out.ogg trim 0.0 0.1
