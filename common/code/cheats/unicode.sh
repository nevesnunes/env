#!/bin/sh

# normalize unicode
python3 -c "import re, sys, unicodedata; print(unicodedata.normalize('NFKD', re.sub(r'[^\w]', '_', sys.argv[1])).encode( 'ASCII', 'ignore').decode('utf-8'))"

# unicode code point to hex

python3 -c 'import sys; sys.stdout.write("".join([chr(int(i, 16)) for i in sys.argv[1:]]).encode("utf-8"))' '1f602' 'fe0f'

# References
# - https://stackoverflow.com/questions/6240055/manually-converting-unicode-codepoints-into-utf-8-and-utf-16
# - https://stackoverflow.com/questions/47716217/converting-emojis-to-unicode-and-vice-versa-in-python-3

# variation selector-16 is non-printable, produces seemingly duplicate names

touch 'foo'
touch "$(printf '%b' 'foo\xef\xb8\x8f')"
# || bash: use c-style-escapes
# touch $'foo\xef\xb8\x8f'

ls
# -rw-rw-r--.    1 fn      fn         0 Nov 23 18:42  foo️
rm foo
# rm: cannot remove 'foo': No such file or directory

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
# - https://www.regular-expressions.info/unicode.html
# - https://crashcourse.housegordon.org/coreutils-multibyte-support.html
# - https://www.pixelbeat.org/docs/coreutils_i18n/
# - https://unix.stackexchange.com/questions/160497/number-of-characters-in-a-shell-commands-output
# - https://stackoverflow.com/questions/27331819/whats-the-difference-between-a-character-a-code-point-a-glyph-and-a-grapheme
# - https://stackoverflow.com/questions/24840667/what-is-the-regex-to-extract-all-the-emojis-from-a-string
# - https://stackoverflow.com/questions/36331572/regular-expression-for-capturing-all-skin-tone-variations-of-an-emoji
# > Create two files in a #git repository with equal names, but differing a letter: á = U+00E1; á = U+0061 U+0301. Clone on a mac. #UnicodeHell
#     - https://github.com/Kayvlim/badrepo
# - https://github.com/unicode-org/last-resort-font/

# Matching non-printable unicode characters: \p{C}
# Validation: `{ foo,ㅤ}`
# - https://stackoverflow.com/questions/44034232/undocumented-java-regex-character-class-pc
# - https://github.com/AdoptOpenJDK/openjdk-jdk11/blob/master/src/jdk.scripting.nashorn/share/classes/jdk/nashorn/internal/runtime/regexp/RegExpScanner.java
# - https://github.com/AdoptOpenJDK/openjdk-jdk9u/blob/master/jdk/src/java.base/share/classes/java/util/regex/CharPredicates.java
