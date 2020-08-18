function! HexSearch(...)
    let l:sequence = '' . join(a:000)

    " [ \t]*        | spacing between byte groups
    " [ \t]\+.\{16} | ascii representation of byte groups
    " [0-9a-f]\+:   | hex address
    let l:separator = '[ \t]*\([ \t]\+.\{16}\n\([0-9a-f]\+: \)\)\?'
    let l:address_negative_lookahead = '\([0-9a-f]*: \)\@!'

    " https://stackoverflow.com/questions/56475817/vimscript-execute-search-does-not-work-anymore
    let @/ = join(split(l:sequence, '\w\w\zs'), l:separator) . l:address_negative_lookahead
    execute 'normal /\<cr>'
endfunction
command! -nargs=1 HexSearch :call HexSearch(<f-args>)
nnoremap g/ :HexSearch 
