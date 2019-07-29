set nocompatible

" ####
" #### MAPPINGS
" ####

nnoremap <Space> <C-f>
inoremap <C-l> <Esc>
inoremap <S-Tab> <C-x><C-o>

set pastetoggle=<F2>
nnoremap <F3> :noh<CR>

map ,' ciW''<Esc>P
map ," ciW""<Esc>P

" Sane completion menu
inoremap <expr> <CR> pumvisible() ? "\<C-Y>" : "\<CR>"

" Conserve split on buffer delete
nnoremap <C-c> :bp\|bd #<CR>

" Remove trailing white space
map ,d :%s/\s\+$//<CR>

" Buffers
" map ,b    :ls<CR>:buffer<Space>
map ,o    :b#<CR>
map <C-j> :bp<CR>
map <C-k> :bn<CR>
map <C-h> :tabprevious<CR>
map <C-l> :tabnext<CR>

" Save as sudo
map ,s :w !sudo tee %<CR>

" ####
" #### SETTINGS
" ####

set autochdir
set backupdir=/tmp directory=/tmp
set wildignore+=*.pyc,*.o,*.class,*.lo,.git
set tags=tags;

set number
set cindent
set wildmenu
set tabstop=4 softtabstop=4 shiftwidth=4 expandtab

set completeopt=menu,preview
set diffopt+=iwhite
set viminfo='200,<50,s10,h

" Case insensitive search for lowercase chars
set ignorecase
set smartcase

" Match as you type
set incsearch

" Switch buffers without saving
set hidden

" ####
" #### APPEARANCE
" ####

syntax on
colorscheme default

if has("gui_running")
  map <silent> <S-Insert> "*p
  imap <silent> <S-Insert> <Esc>"*pa
  set guifont=Monospace\ 14
  set guioptions=-m
  set guioptions=-s
  set guioptions-=T
  set guioptions+=c
  set lines=40 columns=84
endif

" Filename in titlebar
autocmd BufEnter * let &titlestring = expand("%:t")
set title

" Set filetype as markdown if detected as text
autocmd BufEnter * if &filetype == "text" | setlocal ft=markdown nocindent | endif

" Set idiotic tab width due to poor decisions in life
autocmd BufRead,BufNewFile *.sh,*.zsh set tabstop=2 softtabstop=2 shiftwidth=2

" CMake
autocmd BufRead,BufNewFile *.cmake,CMakeLists.txt,*.cmake.in runtime! indent/cmake.vim 
autocmd BufRead,BufNewFile *.cmake,CMakeLists.txt,*.cmake.in setf cmake
autocmd BufRead,BufNewFile *.ctest,*.ctest.in setf cmake
