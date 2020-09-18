scriptencoding utf-8
set nocompatible
filetype indent on

" {{{ PLUGINS

set runtimepath+=~/vimfiles

if filereadable(expand('~/.vim/autoload/pathogen.vim'))
    call pathogen#infect()
endif

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
            \ 'header':  ['fg', 'Comment'],
            \ }
let g:fzf_launcher='urxvt -e bash -ic %s'

command! -nargs=+ Z :call fzf#run({
            \'source': 'locate -Ai ' . <f-args>,
            \'sink': 'cd'})<CR>
command! Kno call fzf#run({
            \'source': 'kno.sh ' . expand('%:p') . ':' . line('.') . ':' . substitute(s:LineContext(), ':', ' ', '') . ':' . shellescape(getline('.')),
            \'sink': function('<sid>kno')})
function! s:kno(tags)
    let l:line=getline('.')
    if l:line=~#'^#'
        call setline('.', l:line . ', ' . a:tags)
        normal! $
        return
    endif
    call append(line('.'), '# ' . a:tags)
    normal! j$
endfunction
command! S call s:s_put()
function! s:s_put()
    let l:tmp = tempname()
    silent !clear
    silent !s.sh > l:tmp
    r l:tmp
    silent !rm l:tmp
    redraw!
endfunction

set runtimepath+=~/opt/fzf

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

" Compatibility with other plugins (e.g. `clang_complete`)
" let g:UltiSnipsUsePythonVersion = 2
let g:UltiSnipsUsePythonVersion = 3

" Ale
nmap <F3>] :ALEGoToDefinition<CR>
nmap <F3>f :ALEFix<CR>
nmap <F3>h :ALEHover<CR>
nmap <F3>r :ALEFindReferences<CR>
nmap <F3>t :ALEGoToTypeDefinition<CR>

augroup ale_group
    autocmd!
    autocmd CursorMoved,CursorHold * if exists('*ale#engine#Cleanup') && mode() == 'n' | ALEHover | endif
augroup END
let g:ale_hover_to_preview = 1

let g:ale_cache_executable_check_failures = 1
let g:ale_completion_enabled = 1
let g:ale_completion_tsserver_autoimport = 1
let g:ale_history_log_output = 1
let g:ale_keep_list_window_open = 1
let g:ale_lint_on_text_changed = 'never'
let g:ale_list_window_size = 6
let b:ale_warn_about_trailing_whitespace = 0

let g:ale_fixers = {
            \ 'c': ['clangtidy'],
            \ 'cpp': ['clangtidy'],
            \ 'javascript': ['eslint'],
            \ }
let g:ale_linters = {
            \ 'java': ['javac'],
            \ 'javascript': ['javascript-typescript-stdio', 'tsserver', 'eslint'],
            \ 'python': ['pyls'],
            \ 'sh': ['shellcheck'],
            \ }
let g:ale_linter_alias = {
            \ 'jsx': ['css', 'javascript'],
            \ 'xsd': ['xsd', 'xml'],
            \ 'xslt': ['xslt', 'xml'],
            \ }
let g:ale_pattern_options = {
            \ '\.min\.css$': {'ale_linters': [], 'ale_fixers': []},
            \ '\.min\.js$': {'ale_linters': [], 'ale_fixers': []},
            \}

" Debugging:
" all:
"     :call ch_logfile(expand('~/tmp/channel.log'), 'w')
" c/cpp:
"     bin/compile_commands.json
" java:
"     project/build.gradle
"     :echo ale#java#FindProjectRoot(bufnr(''))
let g:ale_c_parse_compile_commands = 1
let g:ale_css_csslint_options = '--ignore=important'
let g:ale_java_eclipselsp_path = expand('~/opt/eclipse.jdt.ls')
let g:ale_python_pylint_executable = 'run-pylint.sh'
let g:ale_sh_shellcheck_options = '--exclude=SC1090,SC2004,SC2164'

" Syntastic
let g:syntastic_always_populate_loc_list = 1
let g:syntastic_auto_loc_list = 0
let g:syntastic_check_on_open = 1
let g:syntastic_check_on_wq = 1
let g:syntastic_loc_list_height = 6

let g:syntastic_enable_perl_checker = 1
let g:syntastic_perl_checkers = ['perl', 'podchecker']

let g:syntastic_css_csslint_args = '--ignore=important'
let g:syntastic_python_pylint_exe = 'run-pylint.sh'
let g:syntastic_sh_shellcheck_exe = 'shellcheck --exclude=SC1090,SC2004,SC2164'

" autoformat
nnoremap <F5> :Autoformat<CR>
let g:formatdef_autopep8 = '"autopep8 -".(g:DoesRangeEqualBuffer(a:firstline, a:lastline) ? " --range ".a:firstline." ".a:lastline : "")." ".(&textwidth ? "--max-line-length=".&textwidth : "")." --aggressive"'
let g:formatdef_shfmt = '"shfmt -bn -sr -i ".(&expandtab ? shiftwidth() : "0")'
let g:formatters_python = ['black', 'autopep8', 'yapf']

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

" vim-markdown
let g:vim_markdown_folding_disabled = 1
let g:vim_markdown_follow_anchor = 1
let g:vim_markdown_no_extensions_in_markdown = 1
let g:vim_markdown_fenced_languages = ['batch=dosbatch', 'bat=dosbatch', 'csharp=cs', 'powershell=ps1']
map gx <Plug>Markdown_OpenUrlUnderCursor

" vimtex
let g:tex_flavor = 'latex'
let g:vimtex_quickfix_open_on_warning = 0
let g:vimtex_view_method = 'zathura'
let g:vimtex_view_zathura_options = '&>/dev/null'

" web-indent
let g:js_indent_log=0

function! g:Undotree_CustomMap()
    silent! unmap! <buffer> <CR>
    nmap <buffer> <CR> <plug>UndotreeEnter <plug>UndotreeClose
endfunction

function! CursorChars()
    let l:wordcount = wordcount()
    if has_key(l:wordcount, 'cursor_chars')
        return l:wordcount.cursor_chars
    else
        return '_'
    endif
endfunction

function! VimEnterPluginBehaviour()
    if exists(':GundoToggle')
        " Dependencies: python2
        nnoremap <F4> :GundoToggle<CR>
        let g:gundo_close_on_revert = 1
    elseif exists(':UndotreeToggle')
        nnoremap <F4> :UndotreeToggle<CR>
        let g:undotree_SetFocusWhenToggle = 1
    endif

    set statusline=%t
    set statusline+=%#warningmsg#
    if exists('*ALEGetStatusLine')
        set statusline+=%{ALEGetStatusLine()}
    elseif exists('*SyntasticStatuslineFlag')
        set statusline+=%{SyntasticStatuslineFlag()}
    endif
    set statusline+=%*
    "set statusline+=%=0x%B\ \ %{CursorChars()}\ \ %l,%c\ %P
    set statusline+=%=0x%B\ \ %l,%c\ %P
endfunction
augroup vim_enter
    autocmd!
    autocmd VimEnter * call VimEnterPluginBehaviour()
augroup END

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
nmap <silent> ,q :call ToggleList("Quickfix List", 'c')<CR>

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

vmap <Space> "xy:@x<CR>

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
    return lines
endfunction

function! VisualSelectionToString()
    return join(VisualSelection(), "\n")
endfunction

" Open selected text as a URI
" Dependencies: +job
" Otherwise use system()
" References:
" - https://github.com/Carpetsmoker/xdg_open.vim/blob/master/plugin/xdg_open.vim
function! OpenURI(...)
    let l:uri = substitute('' . join(a:000), '^\s*\(.\{-}\)\s*$', '\1', '')
    if empty(l:uri)
        return
    endif

    " Handle brackets being interpreted as invalid character range
    " References:
    " - [Issues with \`:file\` and square brackets / unexpected pattern matching · Issue \#2749 · vim/vim · GitHub](https://github.com/vim/vim/issues/2749)
    try
        let l:uriExpanded = expand(l:uri)
    catch /E944:/
        let l:uri = substitute(l:uri, '^\s*\([^\[]*\)\[\(\([^-]*\)\-\)\+\([^\]]*\)\]\(.*\)$', '\1\\[\2\4]\5', 'g')
        let l:uriExpanded = expand(l:uri)
    endtry

    " If expanded pattern isn't a file, try glob
    if !filereadable(l:uriExpanded)
        let l:files = glob(l:uri)
        if !empty(l:files)
            let l:uriExpanded = split(l:files, "\n")[0]
        endif
    endif

    " Handle relative paths
    if l:uriExpanded =~# '^\.'
        let l:uriExpanded = expand('%:p:h') . '/' . l:uri
    endif

    " Use current editor instance for plaintext files
    if system('file -ib ' . shellescape(l:uriExpanded)) =~# '^text/'
        silent! execute 'edit' l:uriExpanded
        return
    endif

    echomsg 'Opening: ' . l:uriExpanded
    call job_start(['env', 'XDG_CURRENT_DESKTOP=X-Generic', 'xdg-open', l:uriExpanded])
endfunction
nnoremap go :call OpenURI(expand("<cWORD>"))<CR>
" We use our own function to get visual lines, so remove range '<,'> to avoid using the same line more than once.
" Reference: https://stackoverflow.com/questions/36406366/function-is-called-several-times-in-vimscript
vnoremap go :<C-u>call map(VisualSelection(), 'OpenURI(v:val)')<CR>

function! VisualGX(line)
    let l:site = substitute(a:line, '^\s*\(.\{-}\)\s*$', '\1', '')
    if l:site !~? '^https\?:\/\/'
        let l:site = 'https://' . l:site
    endif
    call netrw#BrowseX(l:site, netrw#CheckIfRemote())
endfunction
nnoremap ,x :call VisualGX(getline('.'))<CR>
vnoremap ,x :call VisualGX(getline(getpos('v')[1]))<CR>

" TODO: use text object
" - https://github.com/kana/vim-textobj-user
" - https://github.com/coachshea/vim-textobj-markdown
vnoremap iL :normal 0f(lvt)<CR>

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
if empty(mapcheck(',b'))
    map ,b :ls<CR>:buffer<Space>
endif
if empty(mapcheck(',o'))
    map ,o :b#<CR>
endif
map <C-j> :bn<CR>
map <C-k> :bp<CR>

silent! unmap! <C-i>
imap <C-i> <C-x><C-o>
silent! unmap! <C-l>
map <C-l> <Esc>:pc<CR>:noh<CR>:Match<CR>:redraw!<CR>

" Prevent omnicomplete on tab
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

set completeopt=menu,menuone,preview,noselect,noinsert
set viminfo='200,<50,s10,h

set diffopt+=iwhite
if v:version >= 802
    set diffopt+=algorithm:patience
endif

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

" Referenced by: $VIMRUNTIME/syntax/markdown.vim
let g:markdown_minlines=200

syntax on

set belloff=all
set previewheight=6
set showbreak=╚\  breakindent linebreak

set cmdheight=2
set laststatus=2
set scrolloff=0
set shortmess=a

" Preview window consistent with quickfix windows
set splitbelow
set splitright

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

command! -range FormatShellCmd <line1>!format_shell_cmd.py

augroup filetype_group
    autocmd!
    autocmd BufEnter *
                \ if &filetype !=# 'markdown' && line('$') < 100 |
                \     for i in range(1, line('$')) |
                \         if strlen(getline(i)) >= 500 |
                \             setlocal syntax=off |
                \             break |
                \         endif |
                \     endfor |
                \ endif
    set synmaxcol=800

    autocmd BufWritePost *
                \ if getline(1) =~ "^#!" |
                \     if getline(1) =~ "/bin/" |
                \         silent execute "!chmod a+x <afile>" |
                \         redraw! |
                \     endif |
                \ endif

    " Alternative:
    " redir @">|silent echo '# ' . expand('%:t:r')|redir END|put
    autocmd BufNewFile *.{md,mdx,mdown,mkd,mkdn,mkdown,markdown} put = '# ' . expand('%:t:r') | normal! ggdd2o

    autocmd BufNewFile *.awk 0r ~/code/snippets/recipes/awk | normal! Gdd
    autocmd BufNewFile *.java 0r ~/code/snippets/recipes/java |
                \ for i in range(1, line('$')) |
                \     call setline(i, substitute(getline(i), '%%%', expand('%:t:r'), '')) |
                \ endfor |
                \ normal! 6gg
    autocmd BufNewFile *.py 0r ~/code/snippets/recipes/py | normal! Gdd
    autocmd BufNewFile *.sh 0r ~/code/snippets/recipes/sh | normal! Gdd
    autocmd BufNewFile *.zsh 0r ~/code/snippets/recipes/zsh | normal! Gdd
    autocmd BufNewFile *.yml,*.yaml 0r ~/code/snippets/recipes/yaml | normal! Gdd
    autocmd BufNewFile Makefile* 0r ~/code/snippets/recipes/Makefile | normal! Gddgg
    autocmd BufNewFile package.json 0r ~/code/snippets/recipes/package.json | normal! Gddgg
    autocmd BufRead,BufNewFile *.{diz,DIZ,nfo,NFO} setlocal filetype=nfo

    " Hex mode
    autocmd FileType xml,html,xhtml,json setlocal foldmethod=manual | normal! zR

    " Open folds
    autocmd FileType vim setlocal keywordprg=:help foldmethod=marker | normal! zR
    autocmd FileType xml,html,xhtml,json setlocal foldmethod=manual | normal! zR

    " Documentation, Search
    autocmd FileType markdown noremap K :<C-u>call job_start(['xdg-open', "https://google.com/search?q=" . expand("<C-r><C-w>")])<CR>
    autocmd FileType python noremap K :<C-u>terminal ++close pydoc <C-r><C-w><CR>

    " Quickfix window height
    autocmd FileType qf 6wincmd_

    " Git
    autocmd FileType gitcommit set colorcolumn=73 textwidth=72

    " Langs
    autocmd BufNewFile,BufRead *.sh,*.zsh
                \ setlocal tabstop=2 softtabstop=2 shiftwidth=2 |
                \ setlocal omnifunc=bashcomplete#Complete
    autocmd FileType ruby
                \ setlocal tabstop=2 softtabstop=2 shiftwidth=2
    autocmd BufNewFile,BufRead *.jsx
                \ setlocal filetype=javascript.jsx

    " Make
    autocmd FileType make set noexpandtab
    autocmd BufRead,BufNewFile *.cmake,CMakeLists.txt,*.cmake.in runtime! indent/cmake.vim
    autocmd BufRead,BufNewFile *.cmake,CMakeLists.txt,*.cmake.in setf cmake
    autocmd BufRead,BufNewFile *.ctest,*.ctest.in setf cmake
augroup END

" Previewed files are present in the current directory
let g:netrw_keepdir = 0

function! PreviewFile(...)
    let l:uri = a:1
    if !empty(glob(l:uri))
        let l:type = system('file -ib ' . shellescape(l:uri))
        if l:type =~# '^text/plain'
            silent! execute 'pedit!' l:uri
        elseif l:type =~# '^inode/directory'
            let l:name = tempname()
            set noautochdir
            silent! execute 'pedit! ' . l:name
            wincmd P
            normal! ggdG
            silent! execute 'r !ls ' . l:uri
            normal! ggdd
            wincmd w
        endif
    endif
endfunction
augroup netrw_group
    autocmd!
    autocmd FileType netrw
                \ nnoremap j j:call PreviewFile(expand("<cWORD>"))<CR> |
                \ nnoremap k k:call PreviewFile(expand("<cWORD>"))<CR>
augroup END

" Reference: https://github.com/travisjeffery/vim-auto-mkdir
augroup auto_mkdir
  autocmd!
  autocmd BufWritePre * call s:auto_mkdir(expand('<afile>:p:h'))
  function! s:auto_mkdir(dir)
    if !isdirectory(a:dir)
      call mkdir(iconv(a:dir, &encoding, &termencoding), 'p')
    endif
  endfunction
augroup END

function! HighlightedSynGroup()
    let l:s = synID(line('.'), col('.'), 1)
    echo synIDattr(l:s, 'name') . ' -> ' . synIDattr(synIDtrans(l:s), 'name')
endfunction
command! HighlightedSynGroup call HighlightedSynGroup()

" Highlight multiple search regex patterns
" Usage (native):
"     match My0 /foo\|bar/
"     match none
" Usage (command):
"     Match foo\|bar
"     call matchdelete(w:matches.My0)
" Usage (cli):
"     printf '%s\n' 1 2 3 123 | vim -c 'Match 2\(3\)\@!' -
" References:
" - https://superuser.com/questions/211916/setting-up-multiple-highlight-rules-in-vim
" - https://vim.fandom.com/wiki/Highlight_long_lines
hi My0 cterm=bold ctermbg=magenta guibg=magenta ctermfg=black guifg=black
hi My1 cterm=bold ctermbg=blue    guibg=blue    ctermfg=black guifg=black
hi My2 cterm=bold ctermbg=cyan    guibg=cyan    ctermfg=black guifg=black
hi My3 cterm=bold ctermbg=green   guibg=green   ctermfg=black guifg=black
hi My4 cterm=bold ctermbg=yellow   guibg=yellow   ctermfg=black guifg=black
hi My5 cterm=bold ctermbg=red   guibg=red   ctermfg=black guifg=black
function! Match(...)
    if !exists('w:matches')
        let w:matches = {}
    endif
    if empty(a:000)
        call clearmatches()
        let w:matches = {}
    else
        let l:size = len(keys(w:matches))
        let l:key = 'My' . ((l:size + 0) % 4)
        let l:id = matchadd(l:key, a:1, -1)
        let w:matches[l:key] = l:id
    endif
endfunction
command! -nargs=* Match :call Match(<f-args>)

" }}}

" Load all plugins now.
" Plugins need to be added to runtimepath before helptags can be generated.
packloadall

" Load all of the helptags now, after plugins have been loaded.
" All messages and errors will be ignored.
silent! helptags ALL
