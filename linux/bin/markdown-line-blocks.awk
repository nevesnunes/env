#!/usr/bin/awk -f

/^[^[:space:]].*/ {
    if (started_block == 0) {
        started_block = 1
        split("", blocks)
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
/^$/ {
    if (started_block == 1) {
        if (inside_block == 1) {
            for (i=1; i<=NR; i++) {
                if (blocks[i]) {
                    print "| " blocks[i]
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
