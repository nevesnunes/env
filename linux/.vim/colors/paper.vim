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
            \ '#921050',
            \ '#507640',
            \ '#b84c54',
            \ '#487c98',
            \ '#7254a0',
            \ '#145440',
            \ '#ffffff',
            \ '#000000',
            \ '#921050',
            \ '#507640',
            \ '#b84c54',
            \ '#487c98',
            \ '#7254a0',
            \ '#145440',
            \ '#ffffff']

"
" GUI Colors
"

" 145440 = Dark Green
" 487c98 = Dark Blue
" 921050 = Dark Red
" b84c54 = Orange
" 7254a0 = Violet
" 507640 = Light Green
" d8e4ec = Light Blue

"
" Basic
"

hi Normal guifg=#000000 guibg=#d8e4ec gui=NONE ctermbg=NONE ctermfg=white

hi Boolean   guifg=#7254a0 guibg=NONE gui=bold ctermbg=NONE ctermfg=5 cterm=bold
hi Character guifg=#7254a0 guibg=NONE gui=bold ctermbg=NONE ctermfg=5 cterm=bold
hi Constant  guifg=#7254a0 guibg=NONE gui=bold ctermbg=NONE ctermfg=5 cterm=bold
hi Float     guifg=#7254a0 guibg=NONE gui=bold ctermbg=NONE ctermfg=5 cterm=bold
hi Number    guifg=#7254a0 guibg=NONE gui=bold ctermbg=NONE ctermfg=5 cterm=bold
hi String    guifg=#145440 guibg=NONE gui=NONE ctermbg=NONE ctermfg=5

hi Function   guifg=#507640 guibg=NONE gui=NONE ctermbg=NONE ctermfg=2
hi Identifier guifg=#507640 guibg=NONE gui=bold ctermbg=NONE ctermfg=2 cterm=bold

hi Conditional guifg=#b84c54 guibg=NONE gui=bold ctermbg=NONE ctermfg=3 cterm=bold
hi Exception   guifg=#b84c54 guibg=NONE gui=bold ctermbg=NONE ctermfg=3 cterm=bold
hi Keyword     guifg=#b84c54 guibg=NONE gui=NONE ctermbg=NONE ctermfg=3
hi Label       guifg=#b84c54 guibg=NONE gui=NONE ctermbg=NONE ctermfg=3
hi Operator    guifg=#b84c54 guibg=NONE gui=NONE ctermbg=NONE ctermfg=3
hi Repeat      guifg=#b84c54 guibg=NONE gui=bold ctermbg=NONE ctermfg=3 cterm=bold
hi Statement   guifg=#b84c54 guibg=NONE gui=bold ctermbg=NONE ctermfg=3 cterm=bold

hi Define    guifg=#921050 guibg=NONE gui=NONE ctermbg=NONE ctermfg=4
hi Include   guifg=#921050 guibg=NONE gui=NONE ctermbg=NONE ctermfg=4
hi Macro     guifg=#921050 guibg=NONE gui=NONE ctermbg=NONE ctermfg=4
hi PreCondit guifg=#921050 guibg=NONE gui=NONE ctermbg=NONE ctermfg=4
hi PreProc   guifg=#921050 guibg=NONE gui=NONE ctermbg=NONE ctermfg=4

hi StorageClass guifg=#145440 guibg=NONE gui=bold ctermbg=NONE ctermfg=4 cterm=bold
hi Structure    guifg=#145440 guibg=NONE gui=bold ctermbg=NONE ctermfg=4 cterm=bold
hi Type         guifg=#921050 guibg=NONE gui=bold ctermbg=NONE ctermfg=6 cterm=bold
hi Typedef      guifg=#921050 guibg=NONE gui=NONE ctermbg=NONE ctermfg=6

hi Comment        guifg=#507640 guibg=NONE gui=italic ctermbg=NONE ctermfg=2 cterm=NONE
hi Debug          guifg=#507640 guibg=NONE gui=NONE   ctermbg=NONE ctermfg=6
hi Delimiter      guifg=#507640 guibg=NONE gui=NONE   ctermbg=NONE ctermfg=6
hi Special        guifg=#b84c54 guibg=NONE gui=bold   ctermbg=NONE ctermfg=6 cterm=bold
hi SpecialChar    guifg=#b84c54 guibg=NONE gui=bold   ctermbg=NONE ctermfg=6 cterm=bold
hi SpecialComment guifg=#b84c54 guibg=NONE gui=NONE   ctermbg=NONE ctermfg=6
hi Tag            guifg=#507640 guibg=NONE gui=NONE   ctermbg=NONE ctermfg=6
hi Todo           guifg=#507640 guibg=NONE gui=italic ctermbg=NONE ctermfg=6 cterm=NONE

hi Error      guifg=#921050 guibg=NONE gui=bold           ctermbg=NONE ctermfg=9 cterm=bold
hi Ignore     guifg=#487c98 guibg=NONE gui=italic         ctermbg=NONE ctermfg=4 cterm=NONE
hi Underlines guifg=#000000 guibg=NONE gui=bold,underline ctermbg=NONE ctermfg=6 cterm=bold,underline
hi Underlined guifg=#145440 guibg=NONE gui=bold,underline ctermbg=NONE ctermfg=6 cterm=bold,underline

"
" Extended
"

hi NonText    guifg=#487c98 guibg=NONE gui=NONE ctermbg=NONE ctermfg=4
hi SpecialKey guifg=#b84c54 guibg=NONE gui=NONE ctermbg=NONE ctermfg=6

hi Visual    guifg=#ffffff guibg=#145440 gui=NONE ctermbg=6 ctermfg=black cterm=bold
hi VisualNOS guifg=#ffffff guibg=#487c98 gui=NONE ctermbg=6 ctermfg=white

hi Cursor       guifg=#ffffff guibg=#487c98 gui=NONE ctermbg=4     ctermfg=white
hi CursorColumn guifg=NONE    guibg=#ffffff gui=NONE ctermbg=NONE  ctermfg=white
hi CursorLine   guifg=NONE    guibg=#ffffff gui=NONE ctermbg=NONE  ctermfg=white
hi Directory    guifg=#145440 guibg=NONE    gui=NONE ctermbg=NONE  ctermfg=6
hi VertSplit    guifg=#487c98 guibg=#487c98 gui=bold ctermbg=8     ctermfg=8     cterm=bold
hi Folded       guifg=#487c98 guibg=#d8e4ec gui=NONE ctermbg=NONE  ctermfg=white
hi FoldColumn   guifg=#487c98 guibg=#d8e4ec gui=NONE ctermbg=NONE  ctermfg=white
hi IncSearch    guifg=#ffffff guibg=#145440 gui=NONE ctermbg=white ctermfg=0     cterm=bold
hi LineNr       guifg=#487c98 guibg=#d8e4ec gui=NONE ctermbg=NONE  ctermfg=8     cterm=NONE
hi Question     guifg=#ffffff guibg=#145440 gui=NONE ctermbg=5     ctermfg=black
hi Search       guifg=#ffffff guibg=#145440 gui=NONE ctermbg=6     ctermfg=black cterm=bold
hi Title        guifg=#000000 guibg=NONE    gui=bold ctermbg=NONE  ctermfg=white cterm=bold
hi ErrorMsg     guifg=#ffffff guibg=#921050 gui=NONE ctermbg=1     ctermfg=black
hi WarningMsg   guifg=#ffffff guibg=#145440 gui=NONE ctermbg=5     ctermfg=black
hi Scrollbar    guifg=#d3d3d3 guibg=#a9a7a9 gui=NONE ctermbg=NONE  ctermfg=white
hi Tooltip      guifg=#000000 guibg=#d3d3d3 gui=NONE ctermbg=NONE  ctermfg=white

hi StatusLine   guifg=#d8e4ec guibg=#487c98 gui=bold ctermbg=8    ctermfg=black cterm=bold
hi StatusLineNC guifg=#8cc3ca guibg=#487c98 gui=bold ctermbg=8    ctermfg=3     cterm=bold
hi TabLineFill  guifg=#d8e4ec guibg=#487c98 gui=bold ctermbg=4    ctermfg=black cterm=bold
hi TabLine      guifg=#d8e4ec guibg=#487c98 gui=bold ctermbg=4    ctermfg=black cterm=bold
hi TabLineSel   guifg=#000000 guibg=#d8e4ec gui=bold ctermbg=NONE ctermfg=white cterm=bold
hi WildMenu     guifg=#ffffff guibg=#145440 gui=bold ctermbg=6    ctermfg=black cterm=bold

hi Menu       guifg=#ffffff guibg=#145440 gui=italic ctermbg=4    ctermfg=black cterm=NONE
hi PMenuSbar  guifg=#d8e4ec guibg=#487c98 gui=NONE   ctermbg=8    ctermfg=white
hi PMenuSel   guifg=#ffffff guibg=#145440 gui=bold   ctermbg=6    ctermfg=black cterm=bold
hi PMenu      guifg=#d8e4ec guibg=#487c98 gui=bold   ctermbg=8    ctermfg=black cterm=bold
hi PMenuThumb guifg=#487c98 guibg=#8cc3ca gui=NONE   ctermbg=NONE ctermfg=white

hi cformat           guifg=#b84c54 guibg=NONE    gui=NONE ctermbg=NONE  ctermfg=6
hi cspecialcharacter guifg=#b84c54 guibg=NONE    gui=NONE ctermbg=NONE  ctermfg=6
hi MatchParen        guifg=#ffffff guibg=#145440 gui=bold ctermbg=white ctermfg=blue cterm=bold,reverse term=bold,reverse
hi preproc           guifg=#7254a0 guibg=NONE    gui=NONE ctermbg=NONE  ctermfg=5

hi SignColumn guifg=#487c98 guibg=#d8e4ec gui=bold ctermbg=NONE ctermfg=3 cterm=bold

"
" TeX
"

hi texSubscript   guifg=#000000 guibg=#d8e4ec gui=NONE ctermbg=NONE ctermfg=white cterm=NONE
hi texSuperscript guifg=#000000 guibg=#d8e4ec gui=NONE ctermbg=NONE ctermfg=white cterm=NONE

"
" Diff
"

if (!empty($NO_COLOR) || empty($COLORTERM) || match('linux', $TERM) != -1 || match('dumb', $TERM) != -1)
    hi DiffAdd    guifg=white guibg=#145440 gui=bold,nocombine ctermbg=14    ctermfg=black cterm=bold,nocombine
    hi DiffChange guifg=black guibg=#8cc3ca gui=bold,nocombine ctermbg=13    ctermfg=black cterm=bold,nocombine
    hi DiffDelete guifg=white guibg=#921050 gui=bold,nocombine ctermbg=9     ctermfg=black cterm=bold,nocombine
    hi DiffText   guifg=white guibg=#7254a0 gui=bold,nocombine ctermbg=white ctermfg=black cterm=bold,nocombine
else
    hi DiffAdd    guifg=white guibg=#145440 gui=bold,nocombine ctermbg=34    ctermfg=black cterm=bold,nocombine
    hi DiffChange guifg=black guibg=#8cc3ca gui=bold,nocombine ctermbg=23    ctermfg=white cterm=bold,nocombine
    hi DiffDelete guifg=white guibg=#921050 gui=bold,nocombine ctermbg=210   ctermfg=black cterm=bold,nocombine
    hi DiffText   guifg=white guibg=#7254a0 gui=bold,nocombine ctermbg=96    ctermfg=black cterm=bold,nocombine
endif

"
" Plugins
"

hi ALEWarning     guifg=#7254a0 guibg=NONE gui=bold,underline,nocombine ctermbg=black ctermfg=blue cterm=bold,underline,nocombine
hi ALEError       guifg=#921050 guibg=NONE gui=bold,underline,nocombine ctermbg=black ctermfg=red  cterm=bold,underline,nocombine
hi ALEWarningSign guifg=#7254a0 guibg=NONE gui=bold,nocombine           ctermbg=black ctermfg=blue cterm=bold,nocombine
hi ALEErrorSign   guifg=#921050 guibg=NONE gui=bold,nocombine           ctermbg=black ctermfg=red  cterm=bold,nocombine
