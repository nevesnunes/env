" Vim color file - yotsubaB

if version > 580
    hi clear
    if exists("syntax_on")
        syntax reset
    endif
endif
let g:colors_name = "yotsubaB"


"
" GUI Colors
"

" 117742 = Dark Green
" af0a0f = Dark Red
" 64648f = Dark Violet
" e03f00 = Orange
" 8993cd = Violet
" 789923 = Light Green
" d6daf0 = Light Violet

"
" Basic
"

hi Normal guifg=#000000 guibg=#d6daf0 gui=NONE

hi Boolean   guifg=#64648f guibg=NONE gui=bold
hi Character guifg=#64648f guibg=NONE gui=bold
hi Constant  guifg=#64648f guibg=NONE gui=bold
hi Float     guifg=#64648f guibg=NONE gui=bold
hi Number    guifg=#64648f guibg=NONE gui=bold
hi String    guifg=#117742 guibg=NONE gui=NONE

hi Function   guifg=#789923 guibg=NONE gui=NONE
hi Identifier guifg=#789923 guibg=NONE gui=bold

hi Conditional guifg=#e03f00 guibg=NONE gui=bold
hi Exception   guifg=#e03f00 guibg=NONE gui=bold
hi Keyword     guifg=#e03f00 guibg=NONE gui=NONE
hi Label       guifg=#e03f00 guibg=NONE gui=NONE
hi Operator    guifg=#e03f00 guibg=NONE gui=NONE
hi Repeat      guifg=#e03f00 guibg=NONE gui=bold
hi Statement   guifg=#e03f00 guibg=NONE gui=bold

hi Define    guifg=#af0a0f guibg=NONE gui=NONE
hi Include   guifg=#af0a0f guibg=NONE gui=NONE
hi Macro     guifg=#af0a0f guibg=NONE gui=NONE
hi PreCondit guifg=#af0a0f guibg=NONE gui=NONE
hi PreProc   guifg=#af0a0f guibg=NONE gui=NONE

hi StorageClass guifg=#117742 guibg=NONE gui=bold
hi Structure    guifg=#117742 guibg=NONE gui=bold
hi Type         guifg=#af0a0f guibg=NONE gui=bold
hi Typedef      guifg=#af0a0f guibg=NONE gui=NONE

hi Comment        guifg=#789923 guibg=NONE gui=italic
hi Debug          guifg=#789923 guibg=NONE gui=NONE
hi Delimiter      guifg=#789923 guibg=NONE gui=NONE
hi Special        guifg=#e03f00 guibg=NONE gui=bold
hi SpecialChar    guifg=#e03f00 guibg=NONE gui=bold
hi SpecialComment guifg=#e03f00 guibg=NONE gui=NONE
hi Tag            guifg=#789923 guibg=NONE gui=NONE
hi Todo           guifg=#789923 guibg=NONE gui=italic

hi Error      guifg=#af0a0f guibg=NONE gui=bold
hi Ignore     guifg=#8993cd guibg=NONE gui=italic
hi Underlines guifg=#000000 guibg=NONE gui=bold,underline
hi Underlined guifg=#117742 guibg=NONE gui=bold,underline

"
" Extended
"

hi NonText    guifg=#8993cd guibg=NONE gui=NONE
hi SpecialKey guifg=#e03f00 guibg=NONE gui=NONE

hi Visual    guifg=#ffffff guibg=#e03f00 gui=NONE
hi VisualNOS guifg=#ffffff guibg=#8993cd gui=NONE

hi Cursor       guifg=#000000 guibg=#8993cd gui=NONE
hi CursorColumn guifg=NONE    guibg=#ffffff gui=NONE
hi CursorLine   guifg=NONE    guibg=#ffffff gui=NONE
hi Directory    guifg=#117742 guibg=NONE    gui=NONE
hi VertSplit    guifg=#8993cd guibg=#8993cd gui=bold
hi Folded       guifg=#a0a8b0 guibg=#404048 gui=NONE
hi FoldColumn   guifg=#a0a8b0 guibg=#404048 gui=NONE
hi IncSearch    guifg=#ffffff guibg=#e03f00 gui=NONE
hi LineNr       guifg=#8993cd guibg=#d6daf0 gui=NONE
hi Question     guifg=#ffffff guibg=#117742 gui=NONE
hi Search       guifg=#ffffff guibg=#e03f00 gui=NONE
hi Title        guifg=#000000 guibg=NONE    gui=bold
hi WarningMsg   guifg=#ffffff guibg=#117742 gui=NONE
hi Scrollbar    guifg=#d3d3d3 guibg=#a9a7a9 gui=NONE
hi Tooltip      guifg=#000000 guibg=#d3d3d3 gui=NONE

hi StatusLine   guifg=#d6daf0 guibg=#8993cd gui=bold
hi StatusLineNC guifg=#d6daf0 guibg=#8993cd gui=bold
hi TabLineFill  guifg=#d6daf0 guibg=#8993cd gui=bold
hi TabLine      guifg=#d6daf0 guibg=#8993cd gui=bold
hi TabLineSel   guifg=#000000 guibg=#d6daf0 gui=bold
hi WildMenu     guifg=#ffffff guibg=#e03f00 gui=bold

hi Menu       guifg=#ffffff guibg=#e03f00 gui=italic
hi PMenuSbar  guifg=#000000 guibg=#8993cd gui=NONE
hi PMenuSel   guifg=#ffffff guibg=#e03f00 gui=bold
hi PMenu      guifg=#000000 guibg=#8993cd gui=NONE
hi PMenuThumb guifg=#ffffff guibg=#55567a gui=NONE

hi cformat           guifg=#e03f00 guibg=NONE    gui=NONE
hi cspecialcharacter guifg=#e03f00 guibg=NONE    gui=NONE
hi MatchParen        guifg=#ffffff guibg=#e03f00 gui=bold
hi preproc           guifg=#64648f guibg=NONE    gui=NONE

hi SignColumn guifg=#8993cd guibg=#d6daf0 gui=bold

"
" TeX
"

hi texSubscript   guifg=#000000 guibg=#d6daf0 gui=NONE
hi texSuperscript guifg=#000000 guibg=#d6daf0 gui=NONE

"
" Diff
"

hi DiffAdd    guifg=white guibg=DarkCyan    gui=bold,nocombine
hi DiffChange guifg=white guibg=DarkMagenta gui=bold,nocombine
hi DiffDelete guifg=black guibg=LightRed    gui=bold,nocombine
hi DiffText   guifg=black guibg=white       gui=bold,nocombine
