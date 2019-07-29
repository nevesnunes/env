#!/usr/bin/awk -f

NR == 1 {
    split($0, header)
    width = 0
    for (i = 1; i <= length(header); i++) {
        if (length($i) > width) {
            width = length($i)
        }
    }
}
NR > 1 {
    for (i = 1; i <= length(header); i++) {
        printf "%" width "s | %s\n", header[i], $i
    }
    printf "\n"
}
