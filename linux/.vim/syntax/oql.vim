if exists("b:current_syntax")
    finish
endif

syntax case ignore
syntax sync minlines=200

syn keyword oqlFunction function
syn keyword oqlStatement select from where and or while for var return
syn match oqlLineComment "\(//.*\)\|\(^\s*#.*\)" contains=osDoc
syn match oqlNumber "\<\(0[bB][0-1]\+\|0[0-7]*\|0[xX]\x\+\|\d\(\d\|_\d\)*\)[lL]\=\>"
syn match oqlNumber "\(\<\d\(\d\|_\d\)*\.\(\d\(\d\|_\d\)*\)\=\|\.\d\(\d\|_\d\)*\)\([eE][-+]\=\d\(\d\|_\d\)*\)\=[fFdD]\="
syn match oqlNumber "\<\d\(\d\|_\d\)*[eE][-+]\=\d\(\d\|_\d\)*[fFdD]\=\>"
syn match oqlNumber "\<\d\(\d\|_\d\)*\([eE][-+]\=\d\(\d\|_\d\)*\)\=[fFdD]\>"
syn region oqlComment start="/\*" end="\*/"
syn region oqlString start=+'+ end=+'+ oneline
syn region oqlString start=+"+ end=+"+ oneline

hi def link oqlComment Comment
hi def link oqlLineComment Comment
hi def link oqlFunction Function
hi def link oqlNumber Number
hi def link oqlStatement Statement
hi def link oqlString String

let b:current_syntax = "oql"
