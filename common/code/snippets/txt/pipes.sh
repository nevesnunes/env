#!/bin/bash

# create test files (one character per line)
echo abcdefgh | grep -o . | gzip > /tmp/foo.gz
echo aafbchddjjklsefksi | grep -o . > /tmp/bar

# create pipes for zipping an unzipping
PIPE_GUNZIP=/tmp/$$.gunzip
PIPE_GZIP=/tmp/$$.gzip
mkfifo "$PIPE_GUNZIP"
mkfifo "$PIPE_GZIP"

# use pipes as endpoints for gzip / gunzip
gzip -dc /tmp/foo.gz > "$PIPE_GUNZIP" &
GUNZIP_PID=$!
gzip -c9 > /tmp/foo.gz.INCOMPLETE < "$PIPE_GZIP" &
GZIP_PID=$!

exec 5< "$PIPE_GUNZIP"
exec 6> "$PIPE_GZIP"

read next_match <&5
while read line; do
    if [ "$line" = "$next_match" ]; then
        read next_match <&5
        echo "$line" >&6
    fi

    echo "$line"
done < /tmp/bar

# Close file handles
exec 5<&-
exec 6>&-

# wait for gzip to terminate, replace input with output, clean up
wait $GZIP_PID
mv /tmp/foo.gz.INCOMPLETE /tmp/foo.gz
rm "$PIPE_GZIP"

# wait for gunzip to terminate, clean up
wait $GUNZIP_PID
rm "$PIPE_GUNZIP"

# check result
ls -l /tmp/{foo,bar}*
gzip -dc /tmp/foo.gz
