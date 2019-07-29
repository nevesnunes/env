colorscheme default
hi! link FoldColumn Normal
hi! NonText ctermbg=NONE ctermfg=white guibg=NONE guifg=white
nmap q :q<CR>
setlocal guifont=Terminus nonumber columns=84 lines=64 foldcolumn=2
silent! e ++enc=cp437
silent! match Ignore /\r$/
execute "normal! gg"
redraw!
