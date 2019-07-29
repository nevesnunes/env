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

if term ==? 'cygwin' || has("gui_running")
    " Reset bad escape sequence on exit
    " See: infocmp | grep -io '\(clear\|sgr0\)=[^,]*'
    set t_te+=[0;10m

    " FZF
    command! FZFMru call fzf#run(fzf#wrap({
                \  'source':  v:oldfiles,
                \  'sink':    'e',
                \  'options': '-m -x +s',
                \  'down':    '40%'}))

    map ,b :Buffers<CR>
    map ,c :Commands<CR>
    map ,f :Files<CR>
    map ,h :FZFMru<CR>
    map ,g :Lines<CR>
    map ,s :Snippets<CR>
    map ,t :Tags<CR>
else
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

let g:run_dumper = 'run-win-cmd-dumper.sh'
fu! ShellCmd(vim_cmd, ...)
    " Global shell:
    " exe 'set shell='.join(split(g:msys_shell))
    " set shellcmdflag=-l\ -c
    "
    " See:
    " https://github.com/airblade/vim-system-escape
    let g:unix_shell = $HOME . '\opt\msys64\usr\bin\bash.exe -l -c '
    if has("gui_running")
        let l:source = g:unix_shell . "'" . g:run_dumper . " " . join(a:000) . "'"
        call fzf#run({
                    \'source': l:source,
                    \'options': '-1 -0',
                    \'sink': 'r'})
    else
        execute 'silent ' . a:vim_cmd . l:external_cmd . join(a:000)
    endif
    execute 'redraw!'
endfu
nnoremap ,. viWy:call ShellCmd('', 'o.sh "' . substitute(fnameescape(@"), "\\\\?", "?", "g") . '"')<CR>
vnoremap ,. y:call ShellCmd('', 'o.sh "' . substitute(fnameescape(@"), "\\\\?", "?", "g") . '"')<CR>
nnoremap ,a diW:call ShellCmd('r', 'url-add-label.sh "' . substitute(@", "#", "\\\\#", "g") . '"')<CR>
vnoremap ,a d:call ShellCmd('r', 'url-add-label.sh "' . substitute(@", "#", "\\\\#", "g")  . '"')<CR>

" }}}
" {{{ APPEARANCE

set t_Co=8
set laststatus=2

if has("gui_running")
    set background=dark
    if v:version > 800
        colorscheme yotsubaB
    else
        " Match dark background of terminal window (vimrun)
        colorscheme snow
    endif

    set guifont=Consolas:h14:cANSI
endif

" }}}
" vim: foldmethod=marker foldopen=all
