" plugin/foo.vim

command! -bang -nargs=* Bar call foo#Bar('cmd', <q-args>)

" autoload/foo.vim

function! foo#Bar(cmd, args)
endfunction
