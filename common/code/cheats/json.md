# Flatten

https://sqlite.org/json1.html#jtree
```sql
  SELECT big.rowid, fullkey, value
    FROM big, json_tree(big.json)
   WHERE json_tree.type NOT IN ('object','array');
```

https://github.com/hercules-team/augeas
```bash
augtool -r . -L --transform 'JSON.lns incl /catj-eg.json'  <<< 'print /files/catj-eg.json'

# Supported Formats
ls  ./share/augeas/lenses/dist/
```

https://blog.tedivm.com/open-source/2017/05/introducing-jsonsmash-work-with-large-json-files-easily/

jq
```bash
jq -j '
  [
    [
      paths(scalars)
      | map(
        if type == "number"
        then "[" + tostring + "]"
        else "." + .
        end
      ) | join("")
    ],
    [
      .. | select(scalars) | @json
    ]
  ]
  | transpose
  | map(join(" = ") + "\n")
  | join("") 
'

jq -r '
  tostream
  | select(length > 1)
  | (
    .[0] | map(
      if type == "number"
      then "[" + tostring + "]"
      else "." + .
      end
    ) | join("")
  ) + " = " + (.[1] | @json)
'

# Reproduce original JSON

jq -r '
 ( tostream
   | select(length > 1)
   | (
     .[0] | map(
       if type == "number"
       then "[" + tostring + "]"
       else "." + .
       end
     ) | join("")
   )
   + " = "
   + (.[1] | @json)
   + " |"
 ),
 "."
'

cat flat.txt | ( jq "$(sed 's/$/ |/;$a.')" <<< '{}' )
```
