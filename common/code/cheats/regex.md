# testing

[Online regex tester and debugger: PHP, PCRE, Python, Golang and JavaScript](https://regex101.com)
[Show HN: Regex Cheatsheet | Hacker News](https://news.ycombinator.com/item?id=22200584)

# lowest common denominator

https://github.com/google/re2/wiki/Syntax

# repeated characters

- `(.)\1+`

# unique characters

- `(?:([A-Za-z])(?!.*\1))*`
- `(?!.*(.).*\1)[A-Za-z]+`

https://stackoverflow.com/questions/12870489/regex-to-match-a-word-with-unique-non-repeating-characters

# between delimiters

```bash
printf '%s' 'a"a`s\"d\"f" sdf `asdf`' \
    | grep -Eo '(["`])((?:\\\1|.)*?)\1'
```

> "a`s\"d\"f"  
> `asdf`  

https://stackoverflow.com/questions/171480/regex-grabbing-values-between-quotation-marks

# word boundaries

```
\B assert position where \b does not match
\b assert position at a word boundary: (^\w|\w$|\W\w|\w\W)
```

```bash
printf '%s' 'abc' | grep -o '\B\w\+'
```

> bc


# lookaround

|Type|Expression|
|---|---|
Lookahead Conditional | `(?(?=...)yes|no)`
Lookbehind Conditional | `(?(?<=...)yes|no)`
Positive Lookahead | `(?=...)`
Negative Lookahead | `(?!...)`
Positive Lookbehind | `(?<=...)`
Negative Lookbehind | `(?<!...)`

https://www.regular-expressions.info/lookaround.html

# regex with back references followed by number

### awk

```awk
awk '{sub("pattern","\\1matched",string);}'
```

### perl

```perl
# replace abcbcd with abcefg, \1 back-reference to matched "abc"
s/(abc)bcd/\1efg/; 
# when there are digits following \1, it can confuse perl, \11 could mean 11th matched group
s/(abc)bcd/\{1}222/;
```

### python

```python
# replace abcbcd with abcefg, \1 back-reference to matched "abc"
import re
re.sub("(abc)bcd","\1efg","abcbcd");
# when there are digits following \1
re.sub("(abc)bcd","\g<1>222","abcbcd");
```

# case studies

https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
    https://nbviewer.jupyter.org/github/rasbt/python_reference/blob/master/tutorials/useful_regex.ipynb
        ~/code/snippets/regex.ipynb


