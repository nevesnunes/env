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

# aggregations

### group by

```bash
<foo.csv awk -F, 'NR>1{arr[$1]++} END{for (a in arr) print a, arr[a]}'
```

- https://stackoverflow.com/a/14916890/8020917

### average, standard deviation

```bash
<foo.csv awk '
{ for (i=1; i<=NF; i++) { sum[i] += $i; sumsq[i] += ($i)^2 } }
END {
    for (i=1;i<=NF;i++) {
        printf "%f %f \n", sum[i]/NR, sqrt((sumsq[i]-sum[i]^2/NR)/NR)
    }
}
'
```

- https://stackoverflow.com/questions/18786073/compute-average-and-standard-deviation-with-awk

Alternatives:

- https://www.gnu.org/software/datamash/

### p95

```bash
sort -u foo.csv | awk '{all[NR] = $0} END{print all[int(NR*0.95 - 0.5)]}'
```

- https://stackoverflow.com/questions/24707705/calculating-95th-percentile-with-awk

# jaccard similarity

```bash
jaccard() {
    comm --total --check-order "$@" | tail -n 1 | awk '{ print ($3 / ($3 + $2 + $1)) }'
}
jaccard <(sort ./foo) <(sort ./bar)
```

- [bashML: Why Spark when you can Bash? \- rev\.ng](https://rev.ng/blog/bashml/post.html)

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
