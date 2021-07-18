if exists('b:after_current_syntax')
  finish
endif
unlet! b:after_current_syntax

silent! syn clear mkdInlineURL
silent! syn clear mkdLineBreak
silent! syn clear mkdLink

" Autolink without angle brackets.
" References:
" https://en.wikipedia.org/wiki/URL#Syntax
syn match mkdInlineURL /\([A-Za-z0-9]\+\)\@<!\(file\|ftp\|https\?\):\/\/\/\?\(\w\+\(:\w\+\)\?@\)\?\([A-Za-z0-9][-_0-9A-Za-z]*\.\?\)\{1,}\(\w\{1,}\.\?\)*\(:[0-9]\{1,5}\)\?\S*/

" Autolink with parenthesis.
syn region mkdInlineURL matchgroup=mkdDelimiter start="(\(\([A-Za-z0-9]\+\)\@<!\(file\|ftp\|https\?\):\/\/\/\?\(\w\+\(:\w\+\)\?@\)\?\([A-Za-z0-9][-_0-9A-Za-z]*\.\)\{1,}\(\w\{1,}\.\?\)\{1,}\(:[0-9]\{1,5}\)\?\S*\)\@=" end=")" oneline

hi! mkdLink ctermfg=6 guifg=cyan cterm=NONE gui=NONE
hi! mkdURL ctermfg=6 guifg=cyan cterm=underline,bold gui=underline,bold
hi! Underlined ctermfg=6 guifg=cyan cterm=underline,bold gui=underline,bold

hi def link mkdInlineURL htmlLink
hi! link mkdURL htmlLink

silent! syn clear htmlTag
syn region htmlTag start=+<[^/]+   end=+>+ fold contains=htmlTagN,htmlString,htmlArg,htmlValue,htmlTagError,htmlEvent,htmlCssDefinition,@htmlPreproc,@htmlArgCluster oneline

silent! syn clear markdownCodeBlock
syn region markdownCodeBlock start="    \|\t" end="$" contains=markdownInlineURL contained
