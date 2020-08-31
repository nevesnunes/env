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

# benchmarking

https://gitlab.gnome.org/GNOME/vte/-/blob/master/perf/vim.sh
    https://gitlab.gnome.org/GNOME/vte/-/blob/master/perf/scroll.vim

# control characters, escape sequences

[XTerm Control Sequences](https://invisible-island.net/xterm/ctlseqs/ctlseqs.html)
[Control Characters and Escape Sequences — Terminal Guide](https://terminalguide.namepad.de/seq/)
[Terminal Sequences \- Google Sheets](https://docs.google.com/spreadsheets/d/19W-lXWS9jYwqCK-LwgYo31GucPPxYVld_hVEcfpNpXg/edit#gid=433919454)
    ~/Downloads/Terminal Sequences.pdf
    ~/Downloads/Terminal Sequences.xlsx
    ~/Downloads/Terminal Sequences.zip
[VT100\.net: Installing and Using the VT320 Video Terminal](https://www.vt100.net/docs/vt320-uu/appendixe.html)

https://gitlab.gnome.org/GNOME/vte/-/blob/38fb480261b192dd73a8edcd22599d0d2fe57f67/src/caps.c
https://gitlab.gnome.org/GNOME/vte/-/blob/bba5901e2cd7fe9c0c7cb30983993d924f793792/src/caps-list.hh
https://gitlab.gnome.org/GNOME/vte/-/blob/master/src/caps.hh

[X11 Color Names](https://www.x.org/releases/X11R7.7/doc/man/man7/X.7.xhtml#heading11)

Extract background color:

```bash
old_stty=$(stty -g)
stty raw -echo min 0 time 0
if [ -n "$TMUX" ]; then
    printf '\ePtmux;\e\e]11;?\a\e\\'
else
    printf '\e]11;?\a'
fi
sleep 0.1
read -r v
stty "$old_stty"
echo $v | sed 's/.*\(rgb:[0-9a-f/]*\).*/\1/'
```

# capabilities

```bash
man 5 termcap
```

~/Downloads/[A Nutshell handbook] Linda Mui, Tim O'Reilly, John Strang - Termcap and Terminfo (1988, O'Reilly).djvu
