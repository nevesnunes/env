scriptencoding utf-8
set nocompatible
filetype indent on

" {{{ PLUGINS

set runtimepath+=~/vimfiles

if filereadable(expand('~/.vim/autoload/pathogen.vim'))
    call pathogen#infect()
endif

" vim-markdown
let g:vim_markdown_folding_disabled = 1
let g:vim_markdown_follow_anchor = 1
let g:vim_markdown_no_extensions_in_markdown = 1
map gx <Plug>Markdown_OpenUrlUnderCursor

" autoformat
nnoremap <F5> :Autoformat<CR>
let g:formatdef_autopep8 = "'autopep8 - --aggressive'"
let g:formatters_python = ['autopep8']

" vimtex
let g:tex_flavor = 'latex'
let g:vimtex_quickfix_open_on_warning = 0
let g:vimtex_view_method = 'zathura'
let g:vimtex_view_zathura_options = '&>/dev/null'

" FZF
let g:fzf_colors = {
            \ 'fg':      ['fg', 'Normal'],
            \ 'bg':      ['bg', 'Normal'],
            \ 'hl':      ['fg', 'Comment'],
            \ 'fg+':     ['fg', 'CursorLine', 'CursorColumn', 'Normal'],
            \ 'bg+':     ['bg', 'CursorLine', 'CursorColumn'],
            \ 'hl+':     ['fg', 'Statement'],
            \ 'info':    ['fg', 'PreProc'],
            \ 'border':  ['fg', 'Ignore'],
            \ 'prompt':  ['fg', 'Conditional'],
            \ 'pointer': ['fg', 'Exception'],
            \ 'marker':  ['fg', 'Keyword'],
            \ 'spinner': ['fg', 'Label'],
            \ 'header':  ['fg', 'Comment'] }

command! -nargs=+ Z :call fzf#run({
            \'source': 'locate -Ai ' . <f-args>,
            \'sink': 'cd'})<CR>
command! Kno call fzf#run({
            \'source': 'kno.sh ' . expand('%:p') . ':' . line('.') . ':' . substitute(s:LineContext(), ':', ' ', '') . ':' . shellescape(getline('.')),
            \'sink': function('<sid>kno')})
fu! s:kno(tags)
    let l:line=getline('.')
    if l:line=~#'^#'
        call setline('.', l:line . ', ' . a:tags)
        normal! $
        return
    endif
    call append(line('.'), '# ' . a:tags)
    normal! j$
endfu
command! S call s:s_put()
fu! s:s_put()
    let l:tmp = tempname()
    silent !clear
    silent !s.sh > l:tmp
    r l:tmp
    silent !rm l:tmp
    redraw!
endfu

set runtimepath+=~/opt/fzf
let g:fzf_launcher='urxvt -e bash -ic %s'

" UltiSnips

" Trigger configuration. Do not use <tab> if you use https://github.com/Valloric/YouCompleteMe.
set runtimepath+=~/code/snippets
let g:UltiSnipsSnippetsDir='~/code/snippets/ultisnips'
let g:UltiSnipsSnippetDirectories=['ultisnips']
let g:UltiSnipsExpandTrigger='<c-o>'
let g:UltiSnipsJumpForwardTrigger='<c-b>'
let g:UltiSnipsJumpBackwardTrigger='<c-z>'

" If you want :UltiSnipsEdit to split your window.
let g:UltiSnipsEditSplit='vertical'

" Compatibility with other plugins (such as `clang_complete`)
" let g:UltiSnipsUsePythonVersion = 2
let g:UltiSnipsUsePythonVersion = 3

" Ale
nmap <F3>] :ALEGoToDefinition<CR>
nmap <F3>h :ALEHover<CR>
nmap <F3>r :ALEFindReferences<CR>
nmap <F3>s :ALESymbolSearch<CR>
nmap <F3>t :ALEGoToTypeDefinition<CR>
augroup ale_group
    autocmd CursorMoved,CursorHold * if exists('*ale#engine#Cleanup') && mode() == 'n' | ALEHover | endif
augroup END

let g:ale_cache_executable_check_failures = 1
let g:ale_completion_enabled = 1
let g:ale_history_log_output = 1
let g:ale_lint_on_text_changed = 'never'

let g:ale_linters = {
            \ 'javascript': ['javascript-typescript-stdio'],
            \ 'python': ['pyls'],
            \ 'sh': ['bash-language-server', 'shellcheck'],
            \}
let g:ale_linter_alias = {
            \ 'xsd': ['xsd', 'xml'],
            \ 'xslt': ['xslt', 'xml']
            \ }

"let b:ale_python_flake8_executable = '/nfs_ds/users/xiyueden/venv/fantasm-venv/bin/flake8'
"let b:ale_python_flake8_use_global = 1
"let b:ale_python_mypy_executable = '/nfs_ds/users/xiyueden/venv/fantasm-venv/bin/mypy'
"let b:ale_python_mypy_use_global = 1
let g:ale_css_csslint_options = '--ignore=important'
let g:ale_python_pylint_executable = 'run-pylint.sh'
let g:ale_sh_shellcheck_options = '--exclude=SC1090,SC2004,SC2164'

" Syntastic
set statusline=%t
set statusline+=%#warningmsg#
if exists('*ALEGetStatusLine')
    set statusline+=%{ALEGetStatusLine()}
endif
if exists('*SyntasticStatuslineFlag')
    set statusline+=%{SyntasticStatuslineFlag()}
endif
set statusline+=%*
set statusline+=%=%l,%c\ %P

let g:syntastic_always_populate_loc_list = 1
let g:syntastic_auto_loc_list = 0
let g:syntastic_check_on_open = 1
let g:syntastic_check_on_wq = 1

let g:syntastic_enable_perl_checker = 1
let g:syntastic_perl_checkers = ['perl', 'podchecker']

let g:syntastic_css_csslint_args = '--ignore=important'
let g:syntastic_python_pylint_exe = 'run-pylint.sh'
let g:syntastic_sh_shellcheck_exe = 'shellcheck --exclude=SC1090,SC2004,SC2164'

" Clang
let g:clang_auto_select=0
let g:clang_complete_auto=1
let g:clang_complete_copen=1
let g:clang_complete_macros=1
let g:clang_complete_patterns=1
let g:clang_jumpto_declaration_key='g>'
let g:clang_memory_percent=70
let g:clang_use_library=1
let g:clang_user_options='-I/usr/include -std=c++11'

"set conceallevel=2
"set concealcursor=vin
let g:clang_snippets=1
let g:clang_conceal_snippets=1
let g:clang_snippets_engine='clang_complete'

" Jedi
let g:jedi#auto_close_doc=1
let g:jedi#popup_on_dot=0

" Gundo
nnoremap <F4> :GundoToggle<CR>

let g:gundo_close_on_revert=1

" web-indent
let g:js_indent_log=0

" }}}
" {{{ FUNCTIONS

function! GetBufferList()
    redir => l:buflist
    silent! ls!
    redir END
    return l:buflist
endfunction

function! ToggleList(bufname, pfx)
    let l:buflist = GetBufferList()
    for l:bufnum in map(filter(split(l:buflist, '\n'), 'v:val =~ "'.a:bufname.'"'), 'str2nr(matchstr(v:val, "\\d\\+"))')
        if bufwinnr(l:bufnum) != -1
            exec(a:pfx.'close')
            return
        endif
    endfor
    if a:pfx ==? 'c' && len(getqflist()) == 0
        echohl ErrorMsg
        echomsg 'Quickfix List is Empty.'
        echohl None
        return
    endif
    if a:pfx ==? 'l' && len(getloclist(0)) == 0
        echohl ErrorMsg
        echomsg 'Location List is Empty.'
        echohl None
        return
    endif
    let l:winnr = winnr()
    exec(a:pfx.'open')
    if winnr() != l:winnr
        wincmd p
    endif
endfunction

nmap <silent> ,l :call ToggleList("Location List", 'l')<CR>
nmap <silent> ,e :call ToggleList("Quickfix List", 'c')<CR>

function! s:DiffSaved()
    let l:filetype=&filetype
    diffthis
    vnew | r # | normal! 1Gdd
    diffthis
    exe 'setlocal bt=nofile bh=wipe nobl noswf ro ft=' . l:filetype
endfunction
command! DiffSaved call s:DiffSaved()
command! CompareSaved call s:DiffSaved()

function! s:ToJavaString()
    for i in range(1, line('$'))
        call setline(i, substitute(getline(i), '"', '\\"', 'g'))
        call setline(i, substitute(getline(i), '^', '+ "', 'g'))
        call setline(i, substitute(getline(i), '$', '"', 'g'))
    endfor
    normal! zR
endfunction
command! ToJavaString call s:ToJavaString()

function! s:ToJavaStringFromJsonValues()
    for i in range(1, line('$'))
        call setline(i, substitute(getline(i), '^[^:]*:\s*', '', 'g'))
        call setline(i, substitute(getline(i), '"\s*,', '" +', 'g'))
    endfor
    normal! zR
endfunction
command! ToJavaStringFromJsonValues call s:ToJavaStringFromJsonValues()

" https://github.com/frioux/vim-lost
" https://git.savannah.gnu.org/cgit/diffutils.git/tree/src/diff.c?id=eaa2a24#n464
function! s:LineContext()
    let l:re = get(b:, 'line_context_regex', '\v^[[:alpha:]#$_]')
    let l:found = search(l:re, 'bn', 1, 100)
    if l:found > 0
        let l:line = getline(l:found)
        return l:line
    else
        return '?'
    endif
endfunction
command! LineContext echomsg s:LineContext()

command! Reload bufdo set eventignore-=Syntax | e
command! TagsRegenerate call job_start(['tags-regenerate.sh'])
command! Todo noautocmd vimgrep /TODO\|FIXME/j ** | cw

" }}}
" {{{ MAPPINGS

set pastetoggle=<F2>

noremap L Lzt
noremap H Hzb
nnoremap <Space> <C-f>
nnoremap <C-x>]  <Esc>:exe "ptjump " . expand("<cword>")<Esc>

map ,' ciW''<Esc>P
map ," ciW""<Esc>P
map ,( ciW()<Esc>P

" Search selected text in current buffer
nnoremap g/ viwy/\V<C-R>"<CR>

" Search selected text in all buffers
" DEPENDENCIES: fzf
nnoremap ,/ viwy:Lines <C-R>"<CR>
vnoremap ,/ y:Lines <C-R>"<CR>

function! VisualSelection()
    if mode() ==# 'v'
        let [line_start, column_start] = getpos('v')[1:2]
        let [line_end, column_end] = getpos('.')[1:2]
    else
        let [line_start, column_start] = getpos("'<")[1:2]
        let [line_end, column_end] = getpos("'>")[1:2]
    end
    if (line2byte(line_start)+column_start) > (line2byte(line_end)+column_end)
        let [line_start, column_start, line_end, column_end] =
                    \   [line_end, column_end, line_start, column_start]
    end
    let lines = getline(line_start, line_end)
    if len(lines) == 0
        return ''
    endif
    let lines[-1] = lines[-1][: column_end - 1]
    let lines[0] = lines[0][column_start - 1:]
    return join(lines, "\n")
endfunction

" Open selected text as a URI
" DEPENDENCIES: +job
" Otherwise use system()
" See: https://github.com/Carpetsmoker/xdg_open.vim/blob/master/plugin/xdg_open.vim
function! OpenURI(...)
    let l:wordUnderCursor = '' . join(a:000)
    if !empty(glob(l:wordUnderCursor)) && system('file -ib ' . shellescape(l:wordUnderCursor)) =~# '^text/plain'
        silent! execute 'edit' l:wordUnderCursor
        return
    endif
    echomsg 'Opening: ' . l:wordUnderCursor
    call job_start(['xdg-open', l:wordUnderCursor])
endfunction
nnoremap ,. :call OpenURI(expand("<cWORD>"))<CR>
vnoremap ,. :call OpenURI(VisualSelection())<CR>

function! VisualGX(line)
    let l:site = substitute(a:line, '^\s*\(.\{-}\)\s*$', '\1', '')
    if l:site !~? '^https\?:\/\/'
        let l:site = 'https://' . l:site
    endif
    call netrw#BrowseX(l:site, netrw#CheckIfRemote())
endfunction
nnoremap ,x :call VisualGX(getline('.'))<CR>
vnoremap ,x :call VisualGX(getline(getpos('v')[1]))<CR>

" Sane pasting
nnoremap "+p :set paste<CR>"+p:set nopaste<CR>
nnoremap "*p :set paste<CR>"*p:set nopaste<CR>

" Sane completion menu
"inoremap <expr> <CR> pumvisible() ? "\<C-Y>" : "\<CR>"
"autocmd InsertLeave,CompleteDone * pclose

" Conserve split on buffer delete
nnoremap <C-c> :bp\|bd #<CR>

" Remove trailing white space
command! RemoveWhite %s/\s\+$//
command! TrimWhite RemoveWhite

" Buffers
"map ,b    :ls<CR>:buffer<Space>
map ,o    :b#<CR>
map <C-j> :bn<CR>
map <C-k> :bp<CR>

"silent! unmap! <C-i>
"imap <C-i> <C-x><C-o>
imap <tab> <C-x><C-o>
map  <C-l> <Esc>:pc<CR>:noh<CR>:redraw!<CR>
map! <C-l> <Esc>:pc<CR>:noh<CR>:redraw!<CR>

" Hack to prevent omnicomplete on tab
function! InsertTabWrapper()
    return "\<tab>"
endfunction
inoremap <tab> <c-r>=InsertTabWrapper()<cr>

" }}}
" {{{ BEHAVIOUR

set autochdir
set autoread
set wildignore+=.hg,.git,.svn
set wildignore+=*.aux,*.out,*.toc
set wildignore+=*.jpg,*.bmp,*.gif,*.png,*.jpeg
set wildignore+=*.o,*.lo,*.obj,*.exe,*.dll,*.manifest
set wildignore+=*.spl
set wildignore+=*.luac
set wildignore+=*.pyc
set wildignore+=*.class,*.jar
set wildignore+=*.DS_Store
set wildignore+=*.sw?
set tags=tags;
if isdirectory($HOME . '/tmp')
    set backupdir=~/tmp directory=~/tmp
    set tags+=~/tmp/tags
endif

set number
set cindent
set wildmenu
set tabstop=4 softtabstop=4 shiftwidth=4 expandtab

"set completeopt=menu,preview
set completeopt=menu,menuone,preview,noselect,noinsert
set diffopt+=iwhite
set viminfo='200,<50,s10,h

set hlsearch

" Match case-insensitive file patterns in an autocmd
set fileignorecase

" Search down into subdirectories
set path+=**

" Case insensitive search for lowercase chars
set ignorecase
set smartcase

" Match as you type
set incsearch

" Switch buffers without saving
set hidden

" }}}
" {{{ APPEARANCE

syntax on

set belloff=all
set previewheight=6
set showbreak=╚\  breakindent linebreak

set cmdheight=2
set shortmess=a

try
    colorscheme yotsubaB
catch /^Vim\%((\a\+)\)\=:E/
    colorscheme koehler
endtry

if has('gui_running')
    try
        set termguicolors
    catch /^Vim\%((\a\+)\)\=:E/
    endtry

    set guioptions=aci
    set lines=40 columns=60
endif

augroup filetype_group
    autocmd BufEnter *
                \ if &filetype !=# 'markdown' && line('$') < 100 |
                \     for i in range(1, line('$')) |
                \         if strlen(getline(i)) >= 500 |
                \             setlocal syntax=off |
                \             break |
                \         endif |
                \     endfor |
                \ endif
    set synmaxcol=500

    autocmd BufWritePost *
                \ if getline(1) =~ "^#!" |
                \     if getline(1) =~ "/bin/" |
                \         silent execute "!chmod a+x <afile>" |
                \         redraw! |
                \     endif |
                \ endif

    autocmd BufNewFile *.py 0r ~/code/snippets/recipes/py | execute "normal! Gdd"
    autocmd BufNewFile *.sh 0r ~/code/snippets/recipes/sh | execute "normal! Gdd"
    autocmd BufNewFile *.yml,*.yaml 0r ~/code/snippets/recipes/yaml | execute "normal! Gdd"
    autocmd BufNewFile Makefile* 0r ~/code/snippets/recipes/Makefile | execute "normal! Gddgg"
    autocmd BufNewFile package.json 0r ~/code/snippets/recipes/package.json | execute "normal! Gddgg"
    autocmd BufRead,BufNewFile *.diz,*.DIZ,*.nfo,*.NFO setlocal filetype=nfo

    " Open folds
    autocmd FileType vim setlocal foldmethod=marker | execute "normal! zR"
    autocmd FileType xml,html,xhtml,json setlocal foldmethod=manual | execute "normal! zR"

    " Git
    autocmd FileType gitcommit set colorcolumn=73 textwidth=72

    " Langs
    autocmd BufRead,BufNewFile *.sh,*.zsh
                \ setlocal tabstop=2 softtabstop=2 shiftwidth=2 |
                \ setlocal omnifunc=bashcomplete#Complete
    autocmd FileType ruby
                \ setlocal tabstop=2 softtabstop=2 shiftwidth=2

    " Make
    autocmd FileType make set noexpandtab
    autocmd BufRead,BufNewFile *.cmake,CMakeLists.txt,*.cmake.in runtime! indent/cmake.vim
    autocmd BufRead,BufNewFile *.cmake,CMakeLists.txt,*.cmake.in setf cmake
    autocmd BufRead,BufNewFile *.ctest,*.ctest.in setf cmake
augroup END

" Previewed files are present in the current directory
let g:netrw_keepdir = 0

function! PreviewFile(...)
    let l:wordUnderCursor = a:1
    if !empty(glob(l:wordUnderCursor))
        let l:type = system('file -ib ' . shellescape(l:wordUnderCursor))
        if l:type =~# '^text/plain'
            silent! execute 'pedit!' l:wordUnderCursor
        elseif l:type =~# '^inode/directory'
            let l:name = tempname()
            set noautochdir
            silent! execute 'pedit! ' . l:name
            wincmd P
            normal! ggdG
            silent! execute 'r !ls ' . l:wordUnderCursor
            normal! ggdd
            wincmd w
        endif
    endif
endfunction
augroup netrw_group
    autocmd FileType netrw
                \ nnoremap j j:call PreviewFile(expand("<cWORD>"))<CR> |
                \ nnoremap k k:call PreviewFile(expand("<cWORD>"))<CR>
augroup END

function! HighlightedSynGroup()
    let l:s = synID(line('.'), col('.'), 1)
    echo synIDattr(l:s, 'name') . ' -> ' . synIDattr(synIDtrans(l:s), 'name')
endfun
command! HighlightedSynGroup call HighlightedSynGroup()

" }}}

" Load all plugins now.
" Plugins need to be added to runtimepath before helptags can be generated.
packloadall
" Load all of the helptags now, after plugins have been loaded.
" All messages and errors will be ignored.
silent! helptags ALL
