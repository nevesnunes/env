# +

```awk
# lowercase conversion
$0 = tolower($0);
# remove non-alphanumeric
gsub("[^a-z]", "", $0);
```

- https://www.grymoire.com/Unix/Awk.html
- https://www.gnu.org/software/gawk/manual/gawk.html

# POSIX compatibility

```bash
gawk -Wposix
mawk -Wposix
```

# delimiters

```bash
echo '1:2 3' | awk -F '[[:space:]:]*' '{print $2 " " $3}'
# 2 3
```

# 2 columns

```bash
seq 1 3 | awk 'NR==1{p=$0; next} {print p " " $0; p=$0}'
```

# permutations

```bash
seq 1 3 | awk '{a[$0]} END{for(i in a) for(j in a) if(i != j){print i " " j}}'
```

Use case: count differences for all pairs

```bash
printf '%s\n' \
    foo \
    bar \
    baz \
    | awk 'NR==1{p=$0; next} {print p " " $0; p=$0}' \
    | xargs -i -n2 bash -c 'diff -Nauw \
        <(./process "$1") \
        <(./process "$2")' {} \
    | grep '^[+-][^+-].*' | sort | uniq -c | vim -c 'set filetype=diff' -
```

# power set

```awk
{
    for(i=0;i<2^NF;i++) {
        for(j=0;j<NF;j++)
            if(and(i,(2^j)))
                printf "%s ",$(j+1)
            print ""
    }
}
```

# case studies

- [GitHub \- step\-/JSON\.awk: Practical JSON parser written in awk](https://github.com/step-/JSON.awk)
