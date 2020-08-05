#!/usr/bin/awk -f

{
    out = $0
    while(1) {
        match($0, /0x[0-9a-f]{4,}/)
        if(RSTART) {
            id = substr($0, RSTART, RLENGTH)
            if (!ids[id]) {
                ids[id] = sprintf("0x%016d", 0)
            }
            $0 = substr($0, RSTART + RLENGTH);
        } else {
            break
        }
    }
    for (id in ids) {
        gsub(id, ids[id], out)
    }
    print out
}
