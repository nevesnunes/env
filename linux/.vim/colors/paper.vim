" Vim color file - paper

if version > 580
    hi clear
    if exists("syntax_on")
        syntax reset
    endif
endif
let g:colors_name = "paper"

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
            \ '#9a2248',
            \ '#115c5a',
            \ '#c5535a',
            \ '#396b84',
            \ '#7d60b0',
            \ '#448058',
            \ '#ffffff',
            \ '#000000',
            \ '#9a2248',
            \ '#115c5a',
            \ '#c5535a',
            \ '#396b84',
            \ '#7d60b0',
            \ '#448058',
            \ '#ffffff']

"
" GUI Colors
"

" 115c5a = Dark Green
" 396b84 = Dark Blue
" 9a2248 = Dark Red
" c5535a = Orange
" 7d60b0 = Violet
" 448058 = Light Green
" d7e0ec = Light Blue

"
" Basic
"

hi Normal guifg=#000000 guibg=#d7e0ec gui=NONE ctermbg=NONE ctermfg=white

hi Boolean   guifg=#7d60b0 guibg=NONE gui=bold ctermbg=NONE ctermfg=5 cterm=bold
hi Character guifg=#7d60b0 guibg=NONE gui=bold ctermbg=NONE ctermfg=5 cterm=bold
hi Constant  guifg=#7d60b0 guibg=NONE gui=bold ctermbg=NONE ctermfg=5 cterm=bold
hi Float     guifg=#7d60b0 guibg=NONE gui=bold ctermbg=NONE ctermfg=5 cterm=bold
hi Number    guifg=#7d60b0 guibg=NONE gui=bold ctermbg=NONE ctermfg=5 cterm=bold
hi String    guifg=#115c5a guibg=NONE gui=NONE ctermbg=NONE ctermfg=5

hi Function   guifg=#448058 guibg=NONE gui=NONE ctermbg=NONE ctermfg=2
hi Identifier guifg=#448058 guibg=NONE gui=bold ctermbg=NONE ctermfg=2 cterm=bold

hi Conditional guifg=#c5535a guibg=NONE gui=bold ctermbg=NONE ctermfg=3 cterm=bold
hi Exception   guifg=#c5535a guibg=NONE gui=bold ctermbg=NONE ctermfg=3 cterm=bold
hi Keyword     guifg=#c5535a guibg=NONE gui=NONE ctermbg=NONE ctermfg=3
hi Label       guifg=#c5535a guibg=NONE gui=NONE ctermbg=NONE ctermfg=3
hi Operator    guifg=#c5535a guibg=NONE gui=NONE ctermbg=NONE ctermfg=3
hi Repeat      guifg=#c5535a guibg=NONE gui=bold ctermbg=NONE ctermfg=3 cterm=bold
hi Statement   guifg=#c5535a guibg=NONE gui=bold ctermbg=NONE ctermfg=3 cterm=bold

hi Define    guifg=#9a2248 guibg=NONE gui=NONE ctermbg=NONE ctermfg=4
hi Include   guifg=#9a2248 guibg=NONE gui=NONE ctermbg=NONE ctermfg=4
hi Macro     guifg=#9a2248 guibg=NONE gui=NONE ctermbg=NONE ctermfg=4
hi PreCondit guifg=#9a2248 guibg=NONE gui=NONE ctermbg=NONE ctermfg=4
hi PreProc   guifg=#9a2248 guibg=NONE gui=NONE ctermbg=NONE ctermfg=4

hi StorageClass guifg=#115c5a guibg=NONE gui=bold ctermbg=NONE ctermfg=4 cterm=bold
hi Structure    guifg=#115c5a guibg=NONE gui=bold ctermbg=NONE ctermfg=4 cterm=bold
hi Type         guifg=#9a2248 guibg=NONE gui=bold ctermbg=NONE ctermfg=6 cterm=bold
hi Typedef      guifg=#9a2248 guibg=NONE gui=NONE ctermbg=NONE ctermfg=6

hi Comment        guifg=#448058 guibg=NONE gui=italic ctermbg=NONE ctermfg=2 cterm=NONE
hi Debug          guifg=#448058 guibg=NONE gui=NONE   ctermbg=NONE ctermfg=6
hi Delimiter      guifg=#448058 guibg=NONE gui=NONE   ctermbg=NONE ctermfg=6
hi Special        guifg=#c5535a guibg=NONE gui=bold   ctermbg=NONE ctermfg=6 cterm=bold
hi SpecialChar    guifg=#c5535a guibg=NONE gui=bold   ctermbg=NONE ctermfg=6 cterm=bold
hi SpecialComment guifg=#c5535a guibg=NONE gui=NONE   ctermbg=NONE ctermfg=6
hi Tag            guifg=#448058 guibg=NONE gui=NONE   ctermbg=NONE ctermfg=6
hi Todo           guifg=#448058 guibg=NONE gui=italic ctermbg=NONE ctermfg=6 cterm=NONE

hi Error      guifg=#9a2248 guibg=NONE gui=bold           ctermbg=NONE ctermfg=9 cterm=bold
hi Ignore     guifg=#396b84 guibg=NONE gui=italic         ctermbg=NONE ctermfg=4 cterm=NONE
hi Underlines guifg=#000000 guibg=NONE gui=bold,underline ctermbg=NONE ctermfg=6 cterm=bold,underline
hi Underlined guifg=#115c5a guibg=NONE gui=bold,underline ctermbg=NONE ctermfg=6 cterm=bold,underline

"
" Extended
"

hi NonText    guifg=#396b84 guibg=NONE gui=NONE ctermbg=NONE ctermfg=4
hi SpecialKey guifg=#c5535a guibg=NONE gui=NONE ctermbg=NONE ctermfg=6

hi Visual    guifg=#ffffff guibg=#c5535a gui=NONE ctermbg=4 ctermfg=black cterm=bold
hi VisualNOS guifg=#ffffff guibg=#396b84 gui=NONE ctermbg=4 ctermfg=white

hi Cursor       guifg=#ffffff guibg=#396b84 gui=NONE ctermbg=4     ctermfg=white
hi CursorColumn guifg=NONE    guibg=#ffffff gui=NONE ctermbg=NONE  ctermfg=white
hi CursorLine   guifg=NONE    guibg=#ffffff gui=NONE ctermbg=NONE  ctermfg=white
hi Directory    guifg=#115c5a guibg=NONE    gui=NONE ctermbg=NONE  ctermfg=6
hi VertSplit    guifg=#396b84 guibg=#396b84 gui=bold ctermbg=8     ctermfg=8     cterm=bold
hi Folded       guifg=#396b84 guibg=#d7e0ec gui=NONE ctermbg=NONE  ctermfg=white
hi FoldColumn   guifg=#396b84 guibg=#d7e0ec gui=NONE ctermbg=NONE  ctermfg=white
hi IncSearch    guifg=#ffffff guibg=#c5535a gui=NONE ctermbg=white ctermfg=0     cterm=bold
hi LineNr       guifg=#396b84 guibg=#d7e0ec gui=NONE ctermbg=NONE  ctermfg=8     cterm=NONE
hi Question     guifg=#ffffff guibg=#115c5a gui=NONE ctermbg=5     ctermfg=black
hi Search       guifg=#ffffff guibg=#c5535a gui=NONE ctermbg=4     ctermfg=black cterm=bold
hi Title        guifg=#000000 guibg=NONE    gui=bold ctermbg=NONE  ctermfg=white cterm=bold
hi ErrorMsg     guifg=#ffffff guibg=#9a2248 gui=NONE ctermbg=1     ctermfg=black
hi WarningMsg   guifg=#ffffff guibg=#115c5a gui=NONE ctermbg=5     ctermfg=black
hi Scrollbar    guifg=#d3d3d3 guibg=#a9a7a9 gui=NONE ctermbg=NONE  ctermfg=white
hi Tooltip      guifg=#000000 guibg=#d3d3d3 gui=NONE ctermbg=NONE  ctermfg=white

hi StatusLine   guifg=#d7e0ec guibg=#396b84 gui=bold ctermbg=8    ctermfg=black cterm=bold
hi StatusLineNC guifg=#8cc3ca guibg=#396b84 gui=bold ctermbg=8    ctermfg=3     cterm=bold
hi TabLineFill  guifg=#d7e0ec guibg=#396b84 gui=bold ctermbg=4    ctermfg=black cterm=bold
hi TabLine      guifg=#d7e0ec guibg=#396b84 gui=bold ctermbg=4    ctermfg=black cterm=bold
hi TabLineSel   guifg=#000000 guibg=#d7e0ec gui=bold ctermbg=NONE ctermfg=white cterm=bold
hi WildMenu     guifg=#ffffff guibg=#c5535a gui=bold ctermbg=4    ctermfg=black cterm=bold

hi Menu       guifg=#ffffff guibg=#c5535a gui=italic ctermbg=3    ctermfg=0     cterm=NONE
hi PMenuSbar  guifg=#d7e0ec guibg=#396b84 gui=NONE   ctermbg=8    ctermfg=white
hi PMenuSel   guifg=#ffffff guibg=#c5535a gui=bold   ctermbg=4    ctermfg=black
hi PMenu      guifg=#d7e0ec guibg=#396b84 gui=bold   ctermbg=0    ctermfg=3
hi PMenuThumb guifg=#396b84 guibg=#8cc3ca gui=NONE   ctermbg=NONE ctermfg=white

hi cformat           guifg=#c5535a guibg=NONE    gui=NONE ctermbg=NONE  ctermfg=6
hi cspecialcharacter guifg=#c5535a guibg=NONE    gui=NONE ctermbg=NONE  ctermfg=6
hi MatchParen        guifg=#ffffff guibg=#c5535a gui=bold ctermbg=white ctermfg=blue cterm=bold,reverse term=bold,reverse
hi preproc           guifg=#7d60b0 guibg=NONE    gui=NONE ctermbg=NONE  ctermfg=5

hi SignColumn guifg=#396b84 guibg=#d7e0ec gui=bold ctermbg=NONE ctermfg=3 cterm=bold

"
" TeX
"

hi texSubscript   guifg=#000000 guibg=#d7e0ec gui=NONE ctermbg=NONE ctermfg=white cterm=NONE
hi texSuperscript guifg=#000000 guibg=#d7e0ec gui=NONE ctermbg=NONE ctermfg=white cterm=NONE

"
" Diff
"

if (!empty($NO_COLOR) || empty($COLORTERM) || match('linux', $TERM) != -1 || match('dumb', $TERM) != -1)
    hi DiffAdd    guifg=white guibg=#115c5a gui=bold,nocombine ctermbg=14    ctermfg=black cterm=bold,nocombine
    hi DiffChange guifg=black guibg=#8cc3ca gui=bold,nocombine ctermbg=13    ctermfg=black cterm=bold,nocombine
    hi DiffDelete guifg=white guibg=#9a2248 gui=bold,nocombine ctermbg=9     ctermfg=black cterm=bold,nocombine
    hi DiffText   guifg=white guibg=#7d60b0 gui=bold,nocombine ctermbg=white ctermfg=black cterm=bold,nocombine
else
    hi DiffAdd    guifg=white guibg=#115c5a gui=bold,nocombine ctermbg=34    ctermfg=black cterm=bold,nocombine
    hi DiffChange guifg=black guibg=#8cc3ca gui=bold,nocombine ctermbg=23    ctermfg=white cterm=bold,nocombine
    hi DiffDelete guifg=white guibg=#9a2248 gui=bold,nocombine ctermbg=210   ctermfg=black cterm=bold,nocombine
    hi DiffText   guifg=white guibg=#7d60b0 gui=bold,nocombine ctermbg=96    ctermfg=black cterm=bold,nocombine
endif

"
" Plugins
"

hi ALEWarning     guifg=#7d60b0 guibg=NONE gui=bold,underline,nocombine ctermbg=black ctermfg=blue cterm=bold,underline,nocombine
hi ALEError       guifg=#9a2248 guibg=NONE gui=bold,underline,nocombine ctermbg=black ctermfg=red  cterm=bold,underline,nocombine
hi ALEWarningSign guifg=#7d60b0 guibg=NONE gui=bold,nocombine           ctermbg=black ctermfg=blue cterm=bold,nocombine
hi ALEErrorSign   guifg=#9a2248 guibg=NONE gui=bold,nocombine           ctermbg=black ctermfg=red  cterm=bold,nocombine

hi markdownId            guifg=#7d60b0 guibg=NONE gui=bold ctermbg=NONE ctermfg=6 cterm=bold
hi markdownIdDeclaration guifg=#7d60b0 guibg=NONE gui=NONE ctermbg=NONE ctermfg=6
hi markdownUrl           guifg=#115c5a guibg=NONE gui=bold,underline ctermbg=NONE ctermfg=6 cterm=bold,underline
