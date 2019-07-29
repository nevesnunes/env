#!/usr/bin/env sh

set -eux

[ -f "$1" ]
[ -f "$2" ]
s1="${1%.*}_spectrogram.png"
s2="${2%.*}_spectrogram.png"
sox "$1" -n rate 44k spectrogram -o "$s1"
sox "$2" -n rate 44k spectrogram -o "$s2"
composite "$s1" "$s2" -compose difference spectrograms_difference.png
