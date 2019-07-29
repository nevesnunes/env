set nocompatible

let term=$TERM
if !has("unix") || term ==? 'cygwin'
    finish
endif

" {{{ PLUGINS

" FZF
map ,b :Buffers<CR>
map ,c :Commands<CR>
map ,f :Files<CR>
map ,h :History<CR>
map ,g :Lines<CR>
map ,s :Snippets<CR>
map ,t :Tags<CR>

let g:fzf_launcher='urxvt -e bash -ic %s'

" }}}
" {{{ FUNCTIONS

" Open selected URI
" DEPENDENCIES: +job
" Otherwise use system()
nnoremap ,. viWy:call job_start(['xdg-open', '<C-R>"'])<CR>:redraw<CR>:echomsg "Running xdg-open..."<CR>
vnoremap ,. y:call job_start(['xdg-open', '<C-R>"'])<CR>:redraw<CR>:echomsg "Running xdg-open..."<CR>

" }}}
" {{{ MAPPINGS

" Save as sudo
map ,w :w !sudo tee %<CR>

" }}}
" {{{ APPEARANCE

if has("gui_running")
  map <silent> <S-Insert> "*p
  imap <silent> <S-Insert> <Esc>"*pa
  set guifont=Monospace\ 14
endif

" Refresh title on buffer change
autocmd BufEnter * let &titlestring = "%t%m%r"
" Filename in titlebar
set title
" Restore old title after leaving Vim
set titleold=
" Tmux escape sequences for changing title
if &term =~# "^tmux.." || &term =~# "^screen.."
  let &t_ts = "\e]2;"
  let &t_fs = "\007"

  " Tmux duplicates part of the old title,
  " so we override it
  auto VimLeave * let &t_ts="\e]2;".hostname()."\007"
endif

" }}}
" vim: foldmethod=marker foldopen=all
