" References:
" - https://github.com/denisidoro/navi/blob/master/docs/cheatsheet_syntax.md

if exists("b:current_syntax")
    finish
endif

syntax sync minlines=200

syn case ignore
syn match naviTag "^%.*$"
syn match naviComment "^#.*$"
syn match naviComment "^;.*$"
syn match naviNumber "\<\(0[bB][0-1]\+\|0[0-7]*\|0[xX]\x\+\|\d\(\d\|_\d\)*\)[lL]\=\>"
syn match naviNumber "\(\<\d\(\d\|_\d\)*\.\(\d\(\d\|_\d\)*\)\=\|\.\d\(\d\|_\d\)*\)\([eE][-+]\=\d\(\d\|_\d\)*\)\=[fFdD]\="
syn match naviNumber "\<\d\(\d\|_\d\)*[eE][-+]\=\d\(\d\|_\d\)*[fFdD]\=\>"
syn match naviNumber "\<\d\(\d\|_\d\)*\([eE][-+]\=\d\(\d\|_\d\)*\)\=[fFdD]\>"
syn region naviString start=+'+ end=+'+ oneline contains=naviVariable
syn region naviString start=+"+ end=+"+ oneline contains=naviVariable
"syn region naviVariable start=+<[^[:alnum:]]\@!+ end=+[^[:alnum:]]\@<!>+ oneline
syn match naviVariable "<[[:alnum:]_]\+>"
syn match naviVariableExpansion "^\$[^:]*:"

hi def link naviComment Comment
hi def link naviVariable Statement
hi def link naviVariableExpansion Statement
hi def link naviNumber Number
hi def link naviString String
hi def link naviTag Constant

let b:current_syntax = "navi"
