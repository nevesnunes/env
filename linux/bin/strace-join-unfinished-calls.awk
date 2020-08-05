#!/usr/bin/gawk -f

match($0, /\[pid *([0-9]+)\](.*) <unfinished \.\.\.>/, a) {
    b[a[1]] = a[2]
    next
}
match($0, /\[pid *([0-9]+)\] <\.\.\. .* resumed>(.*)/, a) {
    print "[pid " a[1] "]" b[a[1]] a[2]
    next
}
{
    print
}
