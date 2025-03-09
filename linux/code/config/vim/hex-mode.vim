" Alternative: ~/.vim/bundle/hexmode
" References: 
" - hooks: ~/.vim/bundle/jupytext.vim
" - xxd: https://vim.fandom.com/wiki/Improved_hex_editing

source ~/.vimrc

function! W()
    windo %!xxd -r
    windo w
    windo %!xxd
endfunction
map <F2> :call W()<CR>

augroup xxd
    autocmd!
    autocmd VimEnter * windo %!xxd
augroup END
