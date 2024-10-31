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

silent! syn clear htmlTag
syn region htmlTag start=+<[^/]+ end=+>+ fold contains=htmlTagN,htmlString,htmlArg,htmlValue,htmlTagError,htmlEvent,htmlCssDefinition,@htmlPreproc,@htmlArgCluster oneline

"silent! syn clear markdownCodeBlock
syn region markdownCodeBlock start="    \|\t" end="$" contains=markdownCode,markdownCodeDelimiter,markdownBlockquote,markdownListMarker,markdownOrderedListMarker,markdownLineBreak,markdownLinkText,markdownItalic,markdownItalicDelimiter,markdownBold,markdownBoldDelimiter,markdownBoldItalic,markdownBoldItalicDelimiter,markdownCode,markdownEscape,@htmlTop,markdownError,markdownValid,markdownInlineURL,mkdInlineURL contained

silent! syn clear markdownBlockquote
syn match markdownBlockquote /^\s*>\s*.*$/

syn match mkdTodo "\<\(TODO\|FIXME\)\>" containedin=ALLBUT,mkdCode,markdownCode,markdownCodeBlock

if !exists("g:terminal_ansi_colors")
    let g:terminal_ansi_colors = []
endif

execute printf("hi! mkdHeading ctermfg=6 guifg=%s cterm=bold gui=bold", get(g:terminal_ansi_colors, 6, 'cyan'))
execute printf("hi! mkdInlineURL ctermfg=6 guifg=%s cterm=underline,bold gui=underline,bold", get(g:terminal_ansi_colors, 6, 'cyan'))
execute printf("hi! mkdTodo ctermfg=1 guifg=%s cterm=bold gui=bold", get(g:terminal_ansi_colors, 1, 'red'))
execute printf("hi markdownId guifg=%s guibg=NONE gui=bold ctermbg=NONE ctermfg=5 cterm=bold", get(g:terminal_ansi_colors, 5, 'magenta'))
execute printf("hi markdownIdDeclaration guifg=%s guibg=NONE gui=NONE ctermbg=NONE ctermfg=5 cterm=bold", get(g:terminal_ansi_colors, 5, 'magenta'))

hi! def link markdownCode String
hi! def link markdownLinkText Title
hi! def link markdownUrl mkdInlineURL
hi! def link mkdURL mkdInlineURL
hi! def link Underlined mkdInlineURL

syntax sync fromstart
