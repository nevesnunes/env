set nocompatible

let term=$TERM
if !has('unix') || term ==? 'cygwin'
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

" }}}
" {{{ MAPPINGS

" Save as sudo
map ,w :w !sudo tee %<CR>

" }}}
" {{{ APPEARANCE

if has('gui_running')
    map <silent> <S-Insert> "*p
    imap <silent> <S-Insert> <Esc>"*pa
    set guifont=Monospace\ 10
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

" Preserve clipboard contents on exit
" Note: `xclip` can return 'Error: target STRING not available'
if executable('xsel')
    autocmd VimLeave * call system('echo -n ' . shellescape(getreg('+')) .
                \ ' | xsel -ib')
elseif executable('xclip')
    autocmd VimLeave * call system('echo -n ' . shellescape(getreg('+')) .
                \ ' | xclip -selection clipboard')
endif

" TODO: https://github.com/KabbAmine/myVimFiles/blob/master/autoload/ka/sys.vim
let g:netrw_browsex_viewer='xdg-open'
nnoremap ,a diW:execute 'r !url-add-label.sh "' . substitute(@", "#", "\\\\#", "g") . '"'<CR>:redraw!<CR>kdd
vnoremap ,a d:execute 'r !url-add-label.sh "' . substitute(@", "#", "\\\\#", "g") . '"'<CR>:redraw!<CR>kdd

set dictionary+=/usr/share/dict/words

" }}}
" vim: foldmethod=marker foldopen=all
