# +

- [jless \- A Command\-Line JSON Viewer](https://jless.io/)
- [GitHub \- antonmedv/fx: Command\-line tool and terminal JSON viewer 🔥](https://github.com/antonmedv/fx)
- [GitHub \- kellyjonbrazil/jc: CLI tool and python library that converts the output of popular command\-line tools, file\-types, and common strings to JSON, YAML, or Dictionaries\. This allows piping of output to tools like jq and simplifying automation scripts\.](https://github.com/kellyjonbrazil/jc)
- [JSON command\-line toolbox \(jq, gron, jc, etc\)](https://racum.blog/articles/json-toolbox/)
- [GitHub \- josephburnett/jd: JSON diff and patch](https://github.com/josephburnett/jd)

# Inconsistent parser behaviour

- [GitHub \- BishopFox/json\-interop\-vuln\-labs: Companion labs to &quot;An Exploration of JSON Interoperability Vulnerabilities&quot;](https://github.com/BishopFox/json-interop-vuln-labs/)
  - [An Exploration of JSON Interoperability Vulnerabilities](https://labs.bishopfox.com/tech-blog/an-exploration-of-json-interoperability-vulnerabilities)
  ```json
  {"test": 1, "test": 2}
  {"test": 1, "test\ud800": 2}
  {"test": 2, "extra": /*, "test": 1, "extra2": */}
  ```
- [Parsing JSON is a Minefield](http://seriot.ch/projects/parsing_json.html)

# Non-Standard Extensions

- python: allows `inf` and `nan`
    - https://docs.python.org/3/library/json.html#infinite-and-nan-number-values

# Prettify

```sh
echo '{"foo": "bar", "baz": [1, 2, 3]}' | python -m json.tool
```

# Diff

- line-oriented
    ```sh
    diff -u \
        <(jq -M --sort-keys . foo.json | gron -) \
        <(jq -M --sort-keys . bar.json | gron -)
    ```
- [GitHub \- trailofbits/graphtage: A semantic diff utility and library for tree\-like files such as JSON, JSON5, XML, HTML, YAML, and CSV\.](https://github.com/trailofbits/graphtage)

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
