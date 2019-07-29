"<C-V> = Visual block

set nocompatible

let term=$TERM
if !has("win32") && term !=? 'cygwin'
    finish
endif

"source $VIMRUNTIME/mswin.vim
"behave mswin

" {{{ PLUGINS

filetype plugin indent on

if executable('fzf') && term ==? 'cygwin'
"if term ==? 'IGNORED'
    " FZF
    set rtp+=~/opt/fzf-vim

    map ,b :Buffers<CR>
    map ,c :Commands<CR>
    map ,f :Files<CR>
    map ,h :History<CR>
    map ,g :Lines<CR>
    map ,s :Snippets<CR>
    map ,t :Tags<CR>
elseif executable('fzy')
    " FZY
    set rtp+=~/opt/fzy-vim

    map ,b :FzyBuffer<CR>
    map ,t :FzyTag<CR>
endif

" }}}
" {{{ FUNCTIONS

set diffexpr=MyDiff()
function! MyDiff()
  let opt = '-a --binary '
  if &diffopt =~ 'icase' | let opt = opt . '-i ' | endif
  if &diffopt =~ 'iwhite' | let opt = opt . '-b ' | endif
  let arg1 = v:fname_in
  if arg1 =~ ' ' | let arg1 = '"' . arg1 . '"' | endif
  let arg2 = v:fname_new
  if arg2 =~ ' ' | let arg2 = '"' . arg2 . '"' | endif
  let arg3 = v:fname_out
  if arg3 =~ ' ' | let arg3 = '"' . arg3 . '"' | endif
  let eq = ''
  if $VIMRUNTIME =~ ' '
	if &sh =~ '\<cmd'
	  let cmd = '"' . $VIMRUNTIME . '\diff"'
	  let eq = ''
	else
	  let cmd = substitute($VIMRUNTIME, ' ', '" ', '') . '\diff"'
	endif
  else
	let cmd = $VIMRUNTIME . '\diff'
  endif
  silent execute '!' . cmd . ' ' . opt . arg1 . ' ' . arg2 . ' > ' . arg3 . eq
endfunction

if has("gui_running")
    nnoremap ,. viWy:execute 'silent !start ' . substitute(fnameescape(@"), "\\\\?", "?", "g")<CR>:redraw!<CR>
    vnoremap ,. y:execute 'silent !start ' . substitute(fnameescape(@"), "\\\\?", "?", "g")<CR>:redraw!<CR>
    nnoremap ,a diW:execute 'silent r!' . $HOME . '\opt\msys64\usr\bin\bash.exe -l -c "url-add-label.sh ' . substitute(@", "#", "\\\\#", "g") . '"'<CR>:redraw!<CR>kdd
    vnoremap ,a d:execute 'silent r!' . $HOME . '\opt\msys64\usr\bin\bash.exe -l -c "url-add-label.sh ' . substitute(@", "#", "\\\\#", "g") . '"'<CR>:redraw!<CR>kdd
else
    nnoremap ,. viWy:execute 'silent !start "" ' . substitute(fnameescape(@"), "\\\\?", "?", "g")<CR>:redraw!<CR>
    vnoremap ,. y:execute 'silent !start "" ' . substitute(fnameescape(@"), "\\\\?", "?", "g")<CR>:redraw!<CR>
    nnoremap ,a diW:execute 'silent r!url-add-label.sh "' . substitute(@", "#", "\\\\#", "g") . '"'<CR>:redraw!<CR>kdd
    vnoremap ,a d:execute 'silent r!url-add-label.sh "' . substitute(@", "#", "\\\\#", "g") . '"'<CR>:redraw!<CR>kdd
endif

" }}}
" {{{ APPEARANCE

set t_Co=8
set laststatus=2

if has("gui_running")
  set guifont=Consolas:h14:cANSI
endif

" }}}
" vim: foldmethod=marker foldopen=all
