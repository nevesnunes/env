" Based on:
" https://github.com/MTDL9/vim-log-highlighting/blob/master/syntax/log.vim

if exists("b:current_syntax")
    finish
endif

syn match log_component '^\(\s*\[[^\]]*\]\)\+'

syn region log_string start=/\(\\\)\@<!'\(s\( \|$\)\|\(t\|$\)\| \w\)\@!/ end=/'/ end=/$/ skip=/\\./ oneline
syn region log_string start=/\(\\\)\@<!"/ end=/"/ skip=/\\./ oneline

syn region log_no_number_region start=/[\/,-]/ end=/[^0-9]\|$/ oneline contains=ALLBUT,log_number
syn region log_number_region start=/^/ end=/$/ contains=ALL
" Don't match number inside base64 value
syn match log_number '\<\d\(\.\d\+\)\+[eE]\?\>' contained
syn match log_number '\<\(+\)\@<!\d\+\(\.\d\+\)*\(+\)\@!\>' contained
syn match log_number '\<0[xX]\x\+\>' contained
syn match log_number '\<0[bB][01]\+\>' contained

" date
syn match log_entity '\<\(Jan\|Feb\|Mar\|Apr\|May\|Jun\|Jul\|Aug\|Sep\|Oct\|Nov\|Dec\) \d\{1,2}\>'
syn match log_entity '\<\d\{4}-\d\d-\d\d\(-\)\@!\>'
" time
syn match log_entity '\<\d\d:\d\d:\d\d\(:\)\@!\>'
syn match log_entity '\<\(\d\{4}-\d\d-\d\dT\)\?\c\d\d:\d\d:\d\d\(\.\d\+\)\=\([+-]\d\d:\d\d\|Z\)\>'
" uuid
syn match log_entity '\<\w\{8}-\w\{4}-\w\{4}-\w\{4}-\w\{12}\(-\)\@!\>'
" md5
syn match log_entity '\<[a-z0-9]\{32}\>'
" ip
syn match log_entity '\<\d\{1,3}\(\.\d\{1,3}\)\{3}\(\.\)\@!\>'
syn match log_entity '\<\x\{1,4}\(:\x\{1,4}\)\{7}\>'
" mac
syn match log_entity '\<\x\{2}\(:\x\{2}\)\{5}\>'

" header
syn match log_xml /<?\(\w\|-\)\+\(\s\+\w\+\(="[^"]*"\|='[^']*'\)\?\)*?>/ contains=log_entity,log_string
" doctype
syn match log_xml /<!DOCTYPE[^>]*>/ contains=log_entity,log_string
" tag
syn match log_xml /<\/\?\(\(\w\|-\)\+:\)\?\(\w\|-\)\+\(\(\n\|\s\)\+\(\(\w\|-\)\+:\)\?\(\w\|-\)\+\(="[^"]*"\|="[^"]*"\)\?\)*\s*\/\?>/ contains=log_entity,log_string

if has("gui_running")
    hi def link log_component Type
    hi def link log_string String
    hi def link log_number String
    hi def link log_entity String
    hi def link log_xml Constant
else
    hi def log_component ctermfg=green guifg=green
    hi def log_string ctermfg=cyan guifg=cyan
    hi def log_number ctermfg=cyan guifg=cyan
    hi def log_entity ctermfg=cyan guifg=cyan
    hi def log_xml ctermfg=yellow guifg=yellow
endif

let b:current_syntax = "log"
