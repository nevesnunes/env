# exit status codes

64-78
    https://man.openbsd.org/sysexits.3
2, 125-128
    http://tldp.org/LDP/abs/html/exitcodes.html
129-154
    https://man.openbsd.org/signal.3

# scancodes

[...] typing a character with the Control key held into a CLI session (real or PTY) causes the TTY driver to receive an octet that looks like that letter ANDed with ~0x40. In other words—referencing an ASCII table—you emit NUL by typing ^@
    -- https://news.ycombinator.com/item?id=22205655

# termcap

https://invisible-island.net/ncurses/ncurses.faq.html#xterm_generic
http://jdebp.uk./Softwares/nosh/guide/commands/TERM.xml#MIS-CONFIGURATION
https://unix.stackexchange.com/a/419092/5132
https://unix.stackexchange.com/a/446912/5132
https://unix.stackexchange.com/a/515517/5132
https://unix.stackexchange.com/a/427299/5132
https://unix.stackexchange.com/a/441899/5132
https://unix.stackexchange.com/a/560992/5132

# fix missed size updates

1. open new pane with desired size, i.e. $ok_pane
2. on $ok_pane: run `stty size` || `tput lines`, take $rows
3. on $nok_pane: run `stty rows $rows`

https://unix.stackexchange.com/questions/86967/change-the-number-of-rows-and-columns-in-the-tty


