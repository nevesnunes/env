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
