" Run command on all buffers

" `vim *`
:argdo %s/Vimcasts\.\zscom/org/ge

" Surround

map ,' ciW''<Esc>P
map ," ciW""<Esc>P
map ,( ciW()<Esc>P

" Delete leading whitespace

:%s/\([a-zA-Z\]"]\+\)[ \t]\+/\1 /g

" Delete blank lines

:g/^$/d
:g/^\_$\n\_^$/d

" Yank 5 chars

y5l

" Insert text at ^ of selected lines

Use Ctrl+V/Ctrl+Q to select the first column of text in the lines you want to comment.
Then hit Shift+i and type the text you want to insert.
Then hit Esc, wait 1 second and the inserted text will appear on every line.

This replaces the beginning of each line with "//":

:%s!^!//!

This replaces the beginning of each selected line (use visual mode to select) with "//":

:'<,'>s!^!//!

" Batch processing

" vim -E -s bob.html <<-EOF
" :%substitute/home.html/index.html/
" :update
" :quit
" EOF

" Bounded keys

:help index

" Replace vi with vim (Fedora)

" cat >/usr/local/bin/vi <<\EOF
" "!/bin/sh
" exec /usr/bin/vim "$@"
" EOF
" chmod 755 /usr/local/bin/vi

" +

:b#
:bufdo s/x/y/g

" Scroll forward one screen    CTRL-f
" Scroll back one screen       CTRL-b        
" 
" Scroll up half a screen      CTRL-u
" Scroll down half a screen    CTRL-d

" Insert text at start of line     I
" Insert text at end of line       A
" 
" Paste line 9 after line 5        :9t 5
" Move line 9 after line 5        :9m 5

" 3diw—delete inside the current word and the next two words
" dwwP—swap the current word with the next word
" d?foo—delete from the cursor to the previous string “foo”
" ct.—change from the cursor until the next period
" d^—delete from the cursor to the beginning of the line
" d>D—delete from the cursor to the end of the line
" 2J—join the current line with the line below
" das—delete around the current sentence
" c(—change from the cursor to the begining of a sentence
" >}—go to the end of the current paragraph
" dapP—swap current paragraph with the next paragraph
