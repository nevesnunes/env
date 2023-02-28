" https://stackoverflow.com/questions/8316139/how-to-set-the-default-to-unfolded-when-you-open-a-file
" setlocal foldmethod=indent iskeyword+=45
silent! :%foldopen!
normal! zR

" ~/.vim/bundle/mdnav/ftplugin/markdown
" silent! nunmap <buffer> <CR>

set expandtab

runtime markdown_folding.vim
