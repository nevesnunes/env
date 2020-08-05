#!/usr/bin/awk -f

/^[^[:space:]].*/ {
    if (started_block == 0) {
        started_block = 1
        split("", blocks)
    }
    # Links and check boxes should be itemized
    match($0, /^\[.*/)
    if (RLENGTH > 0) {
        inside_block = 1
    }
    blocks[NR] = $0
    next
}
/^[[:space:]]+[^[:space:]].*/ {
    if (started_block == 1) {
        inside_block = 1
        blocks[NR] = $0
    } else {
        print
    }
    next
}
# TODO: 
# - Replace ascii markers by emoticons, using octal espace sequences: 
    # - https://rosettacode.org/wiki/Terminal_control/Unicode_output#AWK
    # || Assuming support for unicode sequences:
    # - echo '\u26A0\uFE0F' | awk '{system("/usr/bin/printf \"%b\n\" \"" $1 "\"")}'
# - Add newline between items where next item has initial indent level (i.e. = 0)
# - Add 2 trailing spaces to end of blockquotes, to ensure new lines are preserved
    # - :%s/^\(\s*>.*\)\s*$/\1  /g
# - Escape starting elements in blockquotes
    # - :%s/^\(\s*>\s*\)\*\(\s\+\)/\1\\\*\2/g
# - Add link to URL: <https://foo.com>
    # - https://pandoc.org/MANUAL.html#automatic-links
/^$/ {
    if (started_block == 1) {
        if (inside_block == 1) {
            inside_fence = 0
            for (i=1; i<=NR; i++) {
                inside_ordered_list = 0
                if (blocks[i]) {
                    # Don't itemize fenced blocks
                    match(blocks[i], /^[[:space:]]*```/)
                    if (RLENGTH > 0) {
                        if (inside_fence == 0) {
                            inside_fence = 1
                        } else {
                            inside_fence = 0
                            print blocks[i]
                            continue
                        }
                    }
                    # Don't itemize ordered lists
                    match(blocks[i], /^[[:space:]]*[0-9]+\.[[:space:]]+/)
                    if (RLENGTH > 0) {
                        inside_ordered_list = 1
                    }

                    if (inside_fence == 1 || inside_ordered_list == 1) {
                        print blocks[i]
                        continue
                    }

                    match(blocks[i], /^[[:space:]]+/)
                    if (RLENGTH > 0) {
                        indentation = substr(blocks[i], RSTART, RLENGTH)
                        content = substr(blocks[i], RLENGTH, length(blocks[i]))
                        print indentation "-" content
                    } else {
                        print "- " blocks[i]
                    }
                }
            }
        } else {
            for (i=1; i<=NR; i++) {
                if (blocks[i]) {
                    print blocks[i]
                }
            }
        }
    }
}
{
    started_block = 0
    inside_block = 0
    print
    next
}
