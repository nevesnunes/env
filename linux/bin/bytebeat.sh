#!/usr/bin/env bash

set -eu

trap 'rm -f a.out' EXIT

echo "main(i){
for(i=0;;i++)
putchar(((i*(i>>8|i>>9)&46&i>>8))^(i&i>>13|i>>6));
}" | \
    gcc -x c - && ./a.out | \
    sox -traw -r8000 -b8 -e unsigned-integer - -tpulseaudio
