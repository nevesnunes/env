" https://en.wikipedia.org/wiki/URL#Syntax
syn match markdownInlineURL /\(file\|ftp\|https\?\):\/\/\/\?\(\w\+\(:\w\+\)\?@\)\?\([0-9A-Za-z][-_0-9A-Za-z]*\.\?\)\{1,}\(\w\{2,}\.\?\)\{1,}\(:[0-9]\{1,5}\)\?\S*/
hi def link markdownInlineURL htmlLink

" Override
silent! syn clear htmlTag
syn region htmlTag start=+<[^/]+   end=+>+ fold contains=htmlTagN,htmlString,htmlArg,htmlValue,htmlTagError,htmlEvent,htmlCssDefinition,@htmlPreproc,@htmlArgCluster oneline
silent! syn clear markdownCodeBlock
syn region markdownCodeBlock start="    \|\t" end="$" contains=markdownInlineURL contained
