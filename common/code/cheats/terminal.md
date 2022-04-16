# emulators

- [GitHub \- microsoft/node\-pty: Fork pseudoterminals in Node\.JS](https://github.com/microsoft/node-pty)

# exit status codes

- `0`: EXIT_SUCCESS
- `1`: EXIT_FAILURE
- `2-7`: LSB-specific
    - https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/iniscrptact.html
- `64-78`: BSD-specific
    - https://man.openbsd.org/sysexits.3
    - [D27176 Discourage the use of sysexits\(3\) in new code](https://reviews.freebsd.org/D27176)
- `129-154`: program starts another
    - `2`: Misuse of shell builtins (according to Bash documentation)
    - `126`: Command invoked cannot execute
    - `127`: Command not found
    - `128`: Invalid argument to exit
    - `128 plus the signal number`: process terminated abnormally (note: POSIX only specifies "greater than 128" and that `kill -l` exitstatus can be used to find the signal's short name)
    - https://man.openbsd.org/signal.3
    - http://tldp.org/LDP/abs/html/exitcodes.html
- `200-243`: systemd-specific
    - https://www.freedesktop.org/software/systemd/man/systemd.exec.html#Process%20Exit%20Codes

# scancodes

> [...] typing a character with the Control key held into a CLI session (real or PTY) causes the TTY driver to receive an octet that looks like that letter ANDed with ~0x40. In other words—referencing an ASCII table—you emit NUL by typing ^@
    - https://news.ycombinator.com/item?id=22205655

# termcap

- https://invisible-island.net/ncurses/ncurses.faq.html#xterm_generic
- http://jdebp.uk./Softwares/nosh/guide/commands/TERM.xml#MIS-CONFIGURATION
- [zsh \- Using putty, Left and Right keys move cursor one word, instead of one char \- Unix &amp; Linux Stack Exchange](https://unix.stackexchange.com/a/419092/5132)
- [fish\-shell: shortcut &quot;ctrl\-L&quot; \- Unix &amp; Linux Stack Exchange](https://unix.stackexchange.com/a/446912/5132)
- [terminal \- How important is it that $TERM is correct? \- Unix &amp; Linux Stack Exchange](https://unix.stackexchange.com/a/515517/5132)
- [How to fix anoying vim/terminal behaviour \(vim produces empty lines in terminal\)? \- Unix &amp; Linux Stack Exchange](https://unix.stackexchange.com/a/427299/5132)
- [How to work around terminal artifacts when using dialog program under docker, running in a screen session \- Unix &amp; Linux Stack Exchange](https://unix.stackexchange.com/a/441899/5132)
- [gnome \- Why my colors doesn&\#39;t show in all terminals? \- Unix &amp; Linux Stack Exchange](https://unix.stackexchange.com/a/560992/5132)

# fix missed size updates

1. open new pane with desired size, i.e. $ok_pane
2. on $ok_pane: run `stty size` || `tput lines`, take $rows
3. on $nok_pane: run `stty rows $rows`

- https://unix.stackexchange.com/questions/86967/change-the-number-of-rows-and-columns-in-the-tty

# benchmarking

- https://gitlab.gnome.org/GNOME/vte/-/blob/master/perf/vim.sh
    - https://gitlab.gnome.org/GNOME/vte/-/blob/master/perf/scroll.vim

# control characters, escape sequences

- [XTerm Control Sequences](https://invisible-island.net/xterm/ctlseqs/ctlseqs.html)
- [Control Characters and Escape Sequences — Terminal Guide](https://terminalguide.namepad.de/seq/)
- [Terminal Sequences \- Google Sheets](https://docs.google.com/spreadsheets/d/19W-lXWS9jYwqCK-LwgYo31GucPPxYVld_hVEcfpNpXg/edit#gid=433919454)
    - ~/Downloads/Terminal Sequences.pdf
- [VT100\.net: Installing and Using the VT320 Video Terminal](https://www.vt100.net/docs/vt320-uu/appendixe.html)

- https://gitlab.gnome.org/GNOME/vte/-/blob/38fb480261b192dd73a8edcd22599d0d2fe57f67/src/caps.c
- https://gitlab.gnome.org/GNOME/vte/-/blob/bba5901e2cd7fe9c0c7cb30983993d924f793792/src/caps-list.hh
- https://gitlab.gnome.org/GNOME/vte/-/blob/master/src/caps.hh

- [X11 Color Names](https://www.x.org/releases/X11R7.7/doc/man/man7/X.7.xhtml#heading11)

- ~/bin/keypress-2-control-sequence.sh

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

### alternative charset mode (ACS, VT100 graphics characters)

untic:

```
eA=^[(B^[)0  enable
ae=^O        exit
as=^N        enter
```

session:

```sh
# enable
printf '\x1b(B\x1b)0'
# enter (shift-in)
printf '\x0e'; echo abcdefghijklmnopqrstuvwxyz
# exit (shift-out)
printf '\x0f'; echo abcdefghijklmnopqrstuvwxyz
```

- [DEC Special Graphics \- Wikipedia](https://en.wikipedia.org/wiki/DEC_Special_Graphics)
- [VTTEST &ndash; National Replacement Character Sets](https://invisible-island.net/vttest/vttest-nrcs.html)
- [konsole/vt100\_colorized\_termcap\.txt at master · KDE/konsole · GitHub](https://github.com/KDE/konsole/blob/master/doc/developer/old-documents/More/vt100_colorized_termcap.txt)

### issues

- [NVD \- CVE\-2003\-0063](https://nvd.nist.gov/vuln/detail/CVE-2003-0063)
- ['\(Konsole\-devel\) Fwd: Terminal Emulator Security Issues' \- MARC](https://marc.info/?l=konsole-devel&m=104617524910254&w=2)
- [oss\-security \- Re: zgrep, xzgrep: arbitrary\-file\-write vulnerability](https://www.openwall.com/lists/oss-security/2022/04/08/2)

# capabilities

```bash
man 5 termcap
```

- ~/Downloads/[A Nutshell handbook] Linda Mui, Tim O'Reilly, John Strang - Termcap and Terminfo (1988, O'Reilly).djvu

# reparent tty

```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
tmux
reptyr $(pidof irssi)

# (in another shell)
echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

- [GitHub \- nelhage/reptyr: Reparent a running program to a new terminal](https://github.com/nelhage/reptyr)

# unbuffered

```bash
stty -icanon && nc 127.0.0.1 4501 # sender side
stdbuf -i0 -o0 nc 127.0.0.1 4501 -lk -I 1 # receiver side
```

# limits

```bash
xargs --show-limit </dev/null
```

# case studies

- [tcgetpgrp\(\) behavior and tmux · Issue \#1063 · microsoft/WSL · GitHub](https://github.com/microsoft/WSL/issues/1063)
- [Intermittent client hang after closing stdin to attached container · Issue \#36516 · moby/moby · GitHub](https://github.com/moby/moby/issues/36516)

- [Everything you ever wanted to know about terminals \(2018\) | Hacker News](https://news.ycombinator.com/item?id=24436860)

### ncurses

- [GitHub \- xoreaxeaxeax/sandsifter: The x86 processor fuzzer](https://github.com/xoreaxeaxeax/sandsifter)


