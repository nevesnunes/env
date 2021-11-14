# testing

- [Online regex tester and debugger: PHP, PCRE, Python, Golang and JavaScript](https://regex101.com)
- [Debuggex: Online visual regex tester. JavaScript, Python, and PCRE.](https://www.debuggex.com/r/h3WCCQv-ek1K5VTJ)
- [Show HN: Regex Cheatsheet | Hacker News](https://news.ycombinator.com/item?id=22200584)

# lowest common denominator

https://github.com/google/re2/wiki/Syntax

# repeated characters

- `(.)\1+`

# unique characters

- `(?:([A-Za-z])(?!.*\1))*`
- `(?!.*(.).*\1)[A-Za-z]+`
    - lazy expansion: `(?!.*?(.).*?\1)[A-Za-z]+`

https://stackoverflow.com/questions/12870489/regex-to-match-a-word-with-unique-non-repeating-characters

# multi-byte characters

- input: `\u20AC` or `\x{20AC}`
- invalid stripping
    > In Tcl 8.5 and prior you have to be careful with this syntax, because Tcl used to eat up all hexadecimal characters after \x and treat the last 4 as a Unicode code point. So \xA9ABC20AC would match the euro symbol. Tcl 8.6 only takes the first two hexadecimal digits as part of the \x, as all other regex flavors do, so \xA9ABC20AC matches ©ABC20AC
    - https://www.regular-expressions.info/nonprint.html

# between delimiters

```bash
printf '%s' 'a"a`s\"d\"f" sdf `asdf`' \
    | grep -Eo '(["`])((?:\\\1|.)*?)\1'
# matches: "a`s\"d\"f" `asdf`

printf '%s' 'foo=[123] and bar=[ABC]' \
    | python -c 'import re, sys; print("".join([x for x in re.findall(r"(?=[^\[]+\]).", str(sys.stdin.buffer.read()))]))'
# matches: 123ABC

printf '%s' 'foo=[123] and bar=[ABC]' \
    | node -e 'console.log(fs.readFileSync(0).toString().replace(/(?=[^\[]+\])./g, "*"))'
# replaces with: foo=[***] and bar=[***]
```

https://stackoverflow.com/questions/171480/regex-grabbing-values-between-quotation-marks

# named capture groups

[Verbose regular expressions, now you have one and a bit problems \- Misspelled Nemesis Club](https://moreati.org.uk/blog/2020/06/30/verbose-regular-expressions.html)

# word boundaries

- General Expression
    - `\B`: assert position where `\b` does not match
    - `\b`: assert position at a word boundary: `(^\w|\w$|\W\w|\w\W)` || `(?<!\w)(?=\w)|(?<=\w)(?!\w)`
- Vim Dialect
    - `\<`: assert position at word start
    - `\>`: assert position at word end
- [!] Stops at combining characters, e.g.
    - https://www.sigflag.at/blog/2020/writeup-angstromctf2020-caasio/
    ```
    Expression: /(?:Math(?:(?:\.\w+)|\b))|(?:\d+\.?\d*(?:e\d+)?)/
    Input: MathÐ1
    Matches: Math1
    ```

```bash
printf '%s' 'abc' | grep -o '\B\w\+'
# bc
```

# lookaround

|Type|General Expression|Vim Dialect|
|---|---|
Positive Lookahead | `(?=...)` | `\(...\)\@=`
Negative Lookahead | `(?!...)` | `\(...\)\@!`
Positive Lookbehind | `(?<=...)` | `\(...\)\@<=`
Negative Lookbehind | `(?<!...)` | `\(...\)\@<!`
Lookahead Conditional | `(?(?=...)yes|no)` | `\(\%(condition\)\@=then\|\%(condition\)\@!else\)`
Lookbehind Conditional | `(?(?<=...)yes|no)` | `\(\%(condition\)\@<=then\|\%(condition\)\@<!else\)`

- https://www.regular-expressions.info/lookaround.html
- https://www.regular-expressions.info/conditional.html

### posix alternative

```
s/^foo$/bar/g;
s/^foo\([^a-zA-Z0-9]\)/bar\1/g;
s/\([^a-zA-Z0-9]\)foo$/\1bar/g;
s/\([^a-zA-Z0-9]\)foo\([^a-zA-Z0-9]\)foo\([^a-zA-Z0-9]\)foo\([^a-zA-Z0-9]\)/\1bar\2bar\3bar\4/g;
s/\([^a-zA-Z0-9]\)foo\([^a-zA-Z0-9]\)foo\([^a-zA-Z0-9]\)/\1bar\2bar\3/g;
s/\([^a-zA-Z0-9]\)foo\([^a-zA-Z0-9]\)/\1bar\2/g;
```

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

# parser combinators

- [introduction\-to\-parser\-combinators\.md · GitHub](https://gist.github.com/yelouafi/556e5159e869952335e01f6b473c4ec1)

# performance

- https://learnbyexample.github.io/substitution-with-ripgrep/
- https://swtch.com/~rsc/regexp/

# Blind Regex Injection, REDoS

```
# Backtracking
^(?=(some_regexp_here))((.*)*)*salt$
^some_regexp_here(([^some_char_here])*)*!

# DFA
^some_regexp_here(.?){1000}(.?){1000}...(.?){1000}salt$
```

- ~/code/snippets/ctf/web/regex/
- [CTFtime\.org / TSG CTF 2020 / Slick Logger](https://ctftime.org/task/12273)
- https://blog.p6.is/time-based-regex-injection/
    - https://speakerdeck.com/lmt_swallow/revisiting-redos-a-rough-idea-of-data-exfiltration-by-redos-and-side-channel-techniques
    - https://blog.hackeriet.no/regex-dos-in-java-layer/
- [Regexploit: DoS-able Regular Expressions](https://blog.doyensec.com/2021/03/11/regexploit.html)
- [Stack Exchange Network Status — Outage Postmortem \- July 20, 2016](https://stackstatus.net/post/147710624694/outage-postmortem-july-20-2016)

# case studies

- match "foo" without "bar" (invert matching)
    - use negative lookaround for "bar"
    - or: delete "foo" and "bar" matching lines, then match "foo"

- https://alf.nu/RegexGolf
    - [Best known Regex Golf solutions \(SPOILERS\) \- Classic level set \- \(SPOILERS\) · GitHub](https://gist.github.com/Davidebyzero/9221685)
        - ~/Downloads/Collected solutions for Regex Golf.md
    - [Regex Golf | Hacker News](https://news.ycombinator.com/item?id=6941231)
- [http://play\.inginf\.units\.it solutions · GitHub](https://gist.github.com/pavi2410/d7a6b038ff7d1386ea9dbf3bb5aa6b48)
    - ~/Downloads/play.inginf.units.it-solutions.md
- https://codegolf.stackexchange.com/questions/tagged/regular-expression

- https://mathiasbynens.be/demo/url-regex
- https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
    - https://nbviewer.jupyter.org/github/rasbt/python_reference/blob/master/tutorials/useful_regex.ipynb
        - ~/code/snippets/regex.ipynb
- [Automatic Generation of Text Extraction Patterns from Examples](http://regex.inginf.units.it/)
    - [Automatic Regex Golf Player!](http://regex.inginf.units.it/golf/)
- [GitHub \- MaLeLabTs/RegexGenerator: This project contains the source code of a tool for generating regular expressions for text extraction:  1\. automatically, 2\. based only on examples of the desired behavior, 3\. without any external hint about how the target regex should look like](https://github.com/MaLeLabTs/RegexGenerator)
- [GitHub \- devongovett/regexgen: Generate regular expressions that match a set of strings](https://github.com/devongovett/regexgen)
- [xkcd 1313: Regex Golf (Part 2: Infinite Problems) \- Jupyter Notebook Viewer](https://nbviewer.jupyter.org/url/norvig.com/ipython/xkcd1313-part2.ipynb)
