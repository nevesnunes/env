if exists("b:current_syntax")
    finish
endif

syn keyword osBoolean TRUE FALSE
syn region osComment start="/\*" end="\*/"
syn keyword osConditional if else elseif end
syn match osLineComment "//.*"
syn keyword osFunction function
syn match osNumber "\<\(0[bB][0-1]\+\|0[0-7]*\|0[xX]\x\+\|\d\(\d\|_\d\)*\)[lL]\=\>"
syn match osNumber "\(\<\d\(\d\|_\d\)*\.\(\d\(\d\|_\d\)*\)\=\|\.\d\(\d\|_\d\)*\)\([eE][-+]\=\d\(\d\|_\d\)*\)\=[fFdD]\="
syn match osNumber "\<\d\(\d\|_\d\)*[eE][-+]\=\d\(\d\|_\d\)*[fFdD]\=\>"
syn match osNumber "\<\d\(\d\|_\d\)*\([eE][-+]\=\d\(\d\|_\d\)*\)\=[fFdD]\>"
syn keyword osRepeat for in
syn keyword osStatement return
syn region osString start=+'+ end=+'+ end=+$+
syn region osString start=+"+ end=+"+ end=+$+

syn match osType "\(Assoc\|Boolean\|[CD]API[A-Za-z0-9]*\|Date\|D[Oo][Mm][A-Za-z0-9]*\|Dynamic\|Integer\|Frame\|List\|Object\|RecArray\|Record\|String\|[Vv]oid\)\(\s\+\|$\)" contained
syn region inArgs start="(\s*" end=")" end="[^\s]" end="$" contains=inArgs,osType
syn region inDecl start="^" start="\s\+" end="[^\s]" end="$" contains=ALLBUT,inDecl

hi def link osBoolean Boolean
hi def link osComment Comment
hi def link osConditional Conditional
hi def link osLineComment Comment
hi def link osFunction Function
hi def link osNumber Number
hi def link osRepeat Repeat
hi def link osStatement Statement
hi def link osString String
hi def link osType Type

let b:current_syntax = "oscript"
