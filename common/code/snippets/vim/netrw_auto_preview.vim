set nocompatible
set autochdir

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

autocmd FileType netrw
            \ nnoremap j j:call PreviewFile(expand("<cWORD>"))<CR> |
            \ nnoremap k k:call PreviewFile(expand("<cWORD>"))<CR>
