# Debug

:set vbs=15 vfile=vimdebug
:e _
:set vbs& vfile&
:e vimdebug

:syntime on
" move around in your file and then
:syntime report

http://vimhelp.appspot.com/vim_faq.txt.html#faq-2.5

vim -u NONE -U NONE -N -i NONE
vim -u ~/.vimrc --noplugin -N -i NONE
vim -V15logfile

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
vim -D somefile.txt

" debug a command
debug CommandName

" add breakpoint to function
breakadd func [lineNumber] functionName

" this will write startup info to a file: vim.log
vim --startuptime vim.log

# Jumping

gx, gf, ge (vim-markdown)
