" Faster loading of large files
"
" Alternatives:
" # Divide the file in parts
" split -b 53750k foo
" # Merge the parts
" cat xa* > foo

" Disable filetype syntax highlighting and options
"
" Alternatives:
" syntax off
set eventignore+=FileType

setgl noswap
set binary nospell 
set nobackup
set noswapfile
set nowritebackup
set undofile=
set undolevel=0

set formatoptions-=t
set nowrap
