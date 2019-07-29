" Vim color file - yotsubaB

if version > 580
    hi clear
    if exists("syntax_on")
        syntax reset
    endif
endif
let g:colors_name = "yotsubaB"

"
" CLI Colors
"

" 0  8 = black
" 1  9 = red
" 2 10 = green
" 3 11 = brown/yellow
" 4 12 = blue
" 5 13 = magenta
" 6 14 = cyan
" 7 15 = white
let g:terminal_ansi_colors = [
            \ '#000000',
            \ '#af0a0f',
            \ '#117742',
            \ '#e03f00',
            \ '#8993cd',
            \ '#64648f',
            \ '#789923',
            \ '#ffffff',
            \ '#000000',
            \ '#af0a0f',
            \ '#117742',
            \ '#e03f00',
            \ '#8993cd',
            \ '#64648f',
            \ '#789923',
            \ '#ffffff']

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
" Color similarity table
"

" GUI=#117742/rgb(17,119,66)   Term= 29/#006633/rgb(0,102,51)    [delta=5.759]
" GUI=#AF0A0F/rgb(175,10,15)   Term=124/#990000/rgb(153,0,0)     [delta=4.781]
" GUI=#64648F/rgb(100,100,143) Term=103/#666699/rgb(102,102,153) [delta=2.263]
" GUI=#E03F00/rgb(224,63,0)    Term=166/#CC3300/rgb(204,51,0)    [delta=5.372]
" GUI=#8993CD/rgb(137,147,205) Term=146/#9999CC/rgb(153,153,204) [delta=4.335]
" GUI=#789923/rgb(120,153,35)  Term=107/#669933/rgb(102,153,51)  [delta=4.715]
" GUI=#D6DAF0/rgb(214,218,240) Term=189/#CCCCFF/rgb(204,204,255) [delta=8.821]

"
" Basic
"
hi Normal guifg=#000000 guibg=#d6daf0 gui=NONE ctermbg=NONE ctermfg=white

hi Boolean   guifg=#64648f guibg=NONE gui=bold ctermbg=NONE ctermfg=5 cterm=bold
hi Character guifg=#64648f guibg=NONE gui=bold ctermbg=NONE ctermfg=5 cterm=bold
hi Constant  guifg=#64648f guibg=NONE gui=bold ctermbg=NONE ctermfg=5 cterm=bold
hi Float     guifg=#64648f guibg=NONE gui=bold ctermbg=NONE ctermfg=5 cterm=bold
hi Number    guifg=#64648f guibg=NONE gui=bold ctermbg=NONE ctermfg=5 cterm=bold
hi String    guifg=#117742 guibg=NONE gui=NONE ctermbg=NONE ctermfg=5

hi Function   guifg=#789923 guibg=NONE gui=NONE ctermbg=NONE ctermfg=2
hi Identifier guifg=#789923 guibg=NONE gui=bold ctermbg=NONE ctermfg=2 cterm=bold

hi Conditional guifg=#e03f00 guibg=NONE gui=bold ctermbg=NONE ctermfg=3 cterm=bold
hi Exception   guifg=#e03f00 guibg=NONE gui=bold ctermbg=NONE ctermfg=3 cterm=bold
hi Keyword     guifg=#e03f00 guibg=NONE gui=NONE ctermbg=NONE ctermfg=3
hi Label       guifg=#e03f00 guibg=NONE gui=NONE ctermbg=NONE ctermfg=3
hi Operator    guifg=#e03f00 guibg=NONE gui=NONE ctermbg=NONE ctermfg=3
hi Repeat      guifg=#e03f00 guibg=NONE gui=bold ctermbg=NONE ctermfg=3 cterm=bold
hi Statement   guifg=#e03f00 guibg=NONE gui=bold ctermbg=NONE ctermfg=3 cterm=bold

hi Define    guifg=#af0a0f guibg=NONE gui=NONE ctermbg=NONE ctermfg=4
hi Include   guifg=#af0a0f guibg=NONE gui=NONE ctermbg=NONE ctermfg=4
hi Macro     guifg=#af0a0f guibg=NONE gui=NONE ctermbg=NONE ctermfg=4
hi PreCondit guifg=#af0a0f guibg=NONE gui=NONE ctermbg=NONE ctermfg=4
hi PreProc   guifg=#af0a0f guibg=NONE gui=NONE ctermbg=NONE ctermfg=4

hi StorageClass guifg=#117742 guibg=NONE gui=bold ctermbg=NONE ctermfg=4 cterm=bold
hi Structure    guifg=#117742 guibg=NONE gui=bold ctermbg=NONE ctermfg=4 cterm=bold
hi Type         guifg=#af0a0f guibg=NONE gui=bold ctermbg=NONE ctermfg=6 cterm=bold
hi Typedef      guifg=#af0a0f guibg=NONE gui=NONE ctermbg=NONE ctermfg=6

hi Comment        guifg=#789923 guibg=NONE gui=italic ctermbg=NONE ctermfg=2 cterm=NONE
hi Debug          guifg=#789923 guibg=NONE gui=NONE   ctermbg=NONE ctermfg=6
hi Delimiter      guifg=#789923 guibg=NONE gui=NONE   ctermbg=NONE ctermfg=6
hi Special        guifg=#e03f00 guibg=NONE gui=bold   ctermbg=NONE ctermfg=1 cterm=bold
hi SpecialChar    guifg=#e03f00 guibg=NONE gui=bold   ctermbg=NONE ctermfg=1 cterm=bold
hi SpecialComment guifg=#e03f00 guibg=NONE gui=NONE   ctermbg=NONE ctermfg=3
hi Tag            guifg=#789923 guibg=NONE gui=NONE   ctermbg=NONE ctermfg=6
hi Todo           guifg=#789923 guibg=NONE gui=italic ctermbg=NONE ctermfg=6 cterm=NONE

hi Error      guifg=#af0a0f guibg=NONE gui=bold           ctermbg=NONE ctermfg=9 cterm=bold
hi Ignore     guifg=#8993cd guibg=NONE gui=italic         ctermbg=NONE ctermfg=4 cterm=NONE
hi Underlines guifg=#000000 guibg=NONE gui=bold,underline ctermbg=NONE ctermfg=6 cterm=bold,underline
hi Underlined guifg=#117742 guibg=NONE gui=bold,underline ctermbg=NONE ctermfg=6 cterm=bold,underline

"
" Extended
"

hi NonText    guifg=#8993cd guibg=NONE gui=NONE ctermbg=NONE ctermfg=4
hi SpecialKey guifg=#e03f00 guibg=NONE gui=NONE ctermbg=NONE ctermfg=3

hi Visual    guifg=#ffffff guibg=#e03f00 gui=NONE ctermbg=1 ctermfg=white cterm=bold
hi VisualNOS guifg=#ffffff guibg=#8993cd gui=NONE ctermbg=4 ctermfg=white

hi Cursor       guifg=#000000 guibg=#8993cd gui=NONE ctermbg=4     ctermfg=white
hi CursorColumn guifg=NONE    guibg=#ffffff gui=NONE ctermbg=NONE  ctermfg=white
hi CursorLine   guifg=NONE    guibg=#ffffff gui=NONE ctermbg=NONE  ctermfg=white
hi Directory    guifg=#117742 guibg=NONE    gui=NONE ctermbg=NONE  ctermfg=6
hi VertSplit    guifg=#8993cd guibg=#8993cd gui=bold ctermbg=8     ctermfg=8     cterm=bold
hi Folded       guifg=#a0a8b0 guibg=#404048 gui=NONE ctermbg=NONE  ctermfg=white
hi FoldColumn   guifg=#a0a8b0 guibg=#404048 gui=NONE ctermbg=NONE  ctermfg=white
hi IncSearch    guifg=#ffffff guibg=#e03f00 gui=NONE ctermbg=white ctermfg=0     cterm=bold
hi LineNr       guifg=#8993cd guibg=#d6daf0 gui=bold ctermbg=NONE  ctermfg=8     cterm=NONE
hi Question     guifg=#ffffff guibg=#117742 gui=NONE ctermbg=5     ctermfg=white
hi Search       guifg=#ffffff guibg=#e03f00 gui=NONE ctermbg=1     ctermfg=white cterm=bold
hi Title        guifg=#000000 guibg=NONE    gui=bold ctermbg=NONE  ctermfg=white cterm=bold
hi WarningMsg   guifg=#ffffff guibg=#117742 gui=NONE ctermbg=5     ctermfg=white
hi Scrollbar    guifg=#d3d3d3 guibg=#a9a7a9 gui=NONE ctermbg=NONE  ctermfg=white
hi Tooltip      guifg=#000000 guibg=#d3d3d3 gui=NONE ctermbg=NONE  ctermfg=white

hi StatusLine   guifg=#000000 guibg=#ffffff gui=bold ctermbg=7    ctermfg=0     cterm=NONE
hi StatusLineNC guifg=#d6daf0 guibg=#8993cd gui=bold ctermbg=8    ctermfg=3     cterm=bold
hi TabLineFill  guifg=#d6daf0 guibg=#8993cd gui=bold ctermbg=4    ctermfg=white cterm=bold
hi TabLine      guifg=#d6daf0 guibg=#8993cd gui=bold ctermbg=4    ctermfg=white cterm=bold
hi TabLineSel   guifg=#000000 guibg=#d6daf0 gui=bold ctermbg=NONE ctermfg=white cterm=bold
hi WildMenu     guifg=#ffffff guibg=#e03f00 gui=bold ctermbg=1    ctermfg=white cterm=bold

hi Menu       guifg=#ffffff guibg=#e03f00 gui=italic ctermbg=3    ctermfg=0     cterm=NONE
hi PMenuSbar  guifg=#000000 guibg=#8993cd gui=NONE   ctermbg=8    ctermfg=white
hi PMenuSel   guifg=#ffffff guibg=#e03f00 gui=bold   ctermbg=1    ctermfg=white
hi PMenu      guifg=#000000 guibg=#8993cd gui=NONE   ctermbg=0    ctermfg=3
hi PMenuThumb guifg=#ffffff guibg=#55567a gui=NONE   ctermbg=NONE ctermfg=white

hi cformat           guifg=#e03f00 guibg=NONE    gui=NONE ctermbg=NONE ctermfg=1
hi cspecialcharacter guifg=#e03f00 guibg=NONE    gui=NONE ctermbg=NONE ctermfg=1
hi MatchParen        guifg=#ffffff guibg=#e03f00 gui=bold ctermbg=3    ctermfg=0 cterm=bold
hi preproc           guifg=#64648f guibg=NONE    gui=NONE ctermbg=NONE ctermfg=5

hi SignColumn guifg=#8993cd guibg=#d6daf0 gui=bold ctermbg=NONE ctermfg=3 cterm=bold

"
" TeX
"

hi texSubscript   guifg=#000000 guibg=#d6daf0 gui=NONE ctermbg=NONE ctermfg=white cterm=NONE
hi texSuperscript guifg=#000000 guibg=#d6daf0 gui=NONE ctermbg=NONE ctermfg=white cterm=NONE

"
" Diff
"

hi DiffAdd    guifg=black guibg=LightBlue    gui=nocombine ctermbg=14    ctermfg=black cterm=nocombine
hi DiffChange guifg=white guibg=LightMagenta gui=nocombine ctermbg=13    ctermfg=white cterm=nocombine
hi DiffDelete guifg=black guibg=LightRed     gui=nocombine ctermbg=9     ctermfg=black cterm=nocombine
hi DiffText   guifg=black guibg=white        gui=nocombine ctermbg=white ctermfg=black cterm=nocombine


"
" Plugins
"

hi ALEWarning ctermbg=blue ctermfg=white
hi ALEError   ctermbg=red  ctermfg=white
