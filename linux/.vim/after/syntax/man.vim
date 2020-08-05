if exists('b:after_current_syntax')
  finish
endif
unlet! b:after_current_syntax

" Note: 
" We could match option descriptions (and similar tokens) only at the beginning of a description line, to avoid failure cases of more general patterns (e.g. body text line-breaks makes the matches fail when the token is split at the end of a line). 
" However, tokens at the start of a line of body text would also be matched, while the same tokens in the middle would not. 
" Therefore, a best effort was chosen, by mostly constraining search in single lines. We get a more predictable behaviour, even though multi-line patterns can fail.

" TODO:
" man wget: HSTS entry line, "<LINK REL=", ""no-clobber"", -O/--output-document 
" option parameters: https://stackoverflow.com/questions/32953042/vim-syntax-match-only-when-between-other-matches

" DrChip's additional man.vim stuff
syn case match
syn match manSectionHeading "^\s\+[0-9]\+\.[0-9.]*\s\+[A-Z].*$"
syn match manSectionNumber "^\s\+[0-9]\+\.[0-9]*"
syn match manSubSectionStart "^\*" skipwhite nextgroup=manSubSection
syn match manSubSection ".*$" contained
syn match manBulletZone transparent "^\s\+o\s" contains=manBullet
syn keyword manBullet contained o
syn match manBullet contained "\[+*]"

hi link manSectionHeading Identifier
hi link manSectionNumber Identifier
hi manSubSectionStart term=NONE cterm=NONE gui=NONE ctermfg=black ctermbg=black guifg=navyblue guibg=navyblue
hi manSubSection term=underline cterm=underline gui=underline ctermfg=green guifg=green
hi link manBullet Special

" Validating escaped strings: man curl, man git
syn match manDQString "\"\\\\\?\""
syn region manDQString start='[ \t\[{(]"'hs=s+1 end='[^\\]"' contains=manSQString,manEscapedDQString oneline
syn region manEscapedDQString start='[^a-zA-Z"]\\"[^", )]'lc=1 end='\\"' contained oneline
syn match manSQString "'\\\\\?'"
syn region manSQString start="[ \t\[{(]'"hs=s+1 end="[^\\]'" contains=manDQString,manEscapedSQString oneline
syn region manEscapedSQString start="[ \t]\\'[^', )]"lc=1 end="\\'" contained oneline
syn region manBQString start="[^a-zA-Z`]`[^`, )]"lc=1 end="[`']" oneline
syn region manBQSQString start="``[^),']" end="''" oneline

hi link manDQString String
hi link manEscapedDQString String
hi link manSQString String
hi link manEscapedSQString String
hi link manBQString String
hi link manBQSQString String

" Validating `<...>`: man curl
" Validating `{...}`: man less
syn match manOption "\s\+<[^> \t]\+\([ \t][^> \t]\+\)*\(>\(\([ \t,\.]\@=\)\|$\)\|\(\n\s*\n\)\)" contains=manOption
syn region manOption start="\[" end="\]" end="\n\s*\n" contains=manOption oneline
syn region manOption start="{" end="}" end="\n\s*\n" contains=manOption oneline
hi link manOption String

" \([0-9]\+\.[0-9]\+\): man curl, e.g. --http1.0
" ='[^']*': man wget, e.g. --header='...'
" Lookahead to ignore punctuation: https://askubuntu.com/questions/540235/vi-syntax-highlighting-for-words-followed-by-a-parenthesis
silent! syn clear manOptionDesc
silent! syn clear manLongOptionDesc
syn match manLongOptionDesc "\s\+\(+\|\(--\?\)\)[a-zA-Z0-9_:~!@#%&?+]\+[a-zA-Z0-9_:~!@#%&?+-]*\(=[a-zA-Z0-9,/_-]\+\)\?\(\([ \t,\.]\@=\)\|$\)"
syn match manLongOptionDesc "\s\+\(+\|\(--\?\)\)[a-zA-Z0-9_:~!@#%&?+]\+[a-zA-Z0-9_:~!@#%&?+-]*\(=[a-zA-Z0-9,/_-]\+\)\?\([0-9]\+\.[0-9]\+\)\(\([ \t,\.]\@=\)\|$\)"
syn match manLongOptionDesc "\s\+\(+\|\(--\?\)\)[a-zA-Z0-9_:~!@#%&?+]\+[a-zA-Z0-9_:~!@#%&?+-]*='[^']*'"
syn match manLongOptionDesc '\s\+\(+\|\(--\?\)\)[a-zA-Z0-9_:~!@#%&?+]\+[a-zA-Z0-9_:~!@#%&?+-]*="[^"]*"'
