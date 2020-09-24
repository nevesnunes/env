[ ] reflow text in code block
    e.g. ~/code/doc/+\ first/Martin Fowler - Refactoring - Improving the Design of Existing Code (2ed) (2018, Addison-Wesley Professional).pdf
    ? k2pdfopt
[ ] retrieve text `foo` from stream
    /!\ zlib.decompress() error
        maybe just fonts, if so then ignore

pip install peepdf
https://github.com/jesparza/peepdf

examples
http://eternal-todo.com/blog/cve-2011-2462-exploit-analysis-peepdf
https://quequero.org/2015/09/black-hat-arsenal-peepdf-challenge-2015-writeup/

streams
https://github.com/jesparza/peepdf/blob/c74dc65c0ac7e506bae4f2582a2435ec50741f40/PDFFilters.py#L266
```python
def flateDecode(stream, parameters):
    '''
        Method to decode streams using the Flate algorithm
    
        @param stream: A PDF stream
        @return: A tuple (status,statusContent), where statusContent is the decoded PDF stream in case status = 0 or an error in case status = -1
    '''
    decodedStream = ''
    try:
        decodedStream = zlib.decompress(stream)
    except:
        return (-1, 'Error decompressing string')
```

~/c/wip
a-nowrap.pdf
a-wrap.pdf
a-wrap-uncompressed-qpdf.pdf
a-wrap-with-2span2.pdf
    foo + bar13245
a-wrap-with-2span.pdf
    foo + bar
a-wrap-with-span.pdf
    foo

```bash
pandoc --from=markdown --to=html5 -c "$HOME/env/common/code/web/styles/github.css" --metadata title=a a.md -o a.pdf
cp a.pdf a-wrap-with-2span2.pdf

f=a-wrap-with-2span2.pdf; printf '%s\n%s' 'errors' "$(peepdf "$f" | grep 'Objects ([0-9]*):' | sed 's/.*\[\(.*\)\]/\1/; s/\([0-9]\+\)\(, \)\?/object \1\n/g')"

qpdf --qdf --object-streams=disable a-wrap-with-span.pdf a-wrap-with-span-uncompressed-qpdf.pdf
```


