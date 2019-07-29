" inline links:                protocol   optional  user:pass@       sub/domain                 .com, .co.uk, etc      optional port   path/querystring/hash fragment
"                            ------------ _____________________ --------------------------- ________________________ ----------------- __
syn match markdownInlineURL /\(file\|http\)s\?:\/\/\/\?\(\w\+\(:\w\+\)\?@\)\?\([A-Za-z][-_0-9A-Za-z]*\.\?\)\{1,}\(\w\{2,}\.\?\)\{1,}\(:[0-9]\{1,5}\)\?\S*/
hi def link markdownInlineURL htmlLink

" Override
syn region markdownCodeBlock start="    \|\t" end="$" contains=markdownInlineURL contained
