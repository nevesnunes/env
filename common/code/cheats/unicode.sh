#!/bin/sh

# `wc -m`: number of code points
# `wc -c`: number of bytes

echo a | wc -m
2
echo a | wc -c
2
echo á | wc -m
2
echo á | wc -c
3
echo á | xxd  
00000000: c3a1 0a                                  ...

echo 👏🏿 | wc -m              
3
echo 👏🏿 | wc -c
9
echo 👏🏿 | xxd               
00000000: f09f 918f f09f 8fbf 0a                   .........
echo 👏🏿 | sed 's/./A/' | xxd
00000000: 41f0 9f8f bf0a                           A.....
echo 👏🏿 | sed 's/../A/' | xxd
00000000: 410a                                     A.

# References
# https://www.regular-expressions.info/unicode.html
# https://crashcourse.housegordon.org/coreutils-multibyte-support.html
# https://www.pixelbeat.org/docs/coreutils_i18n/
# https://unix.stackexchange.com/questions/160497/number-of-characters-in-a-shell-commands-output
# https://stackoverflow.com/questions/27331819/whats-the-difference-between-a-character-a-code-point-a-glyph-and-a-grapheme
# https://stackoverflow.com/questions/24840667/what-is-the-regex-to-extract-all-the-emojis-from-a-string
# https://stackoverflow.com/questions/36331572/regular-expression-for-capturing-all-skin-tone-variations-of-an-emoji
