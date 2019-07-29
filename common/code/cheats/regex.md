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
