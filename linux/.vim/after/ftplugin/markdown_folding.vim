function! s:NotCodeBlock(lnum) abort
  let id = synID(v:lnum, 1, 1)
  let attr = synIDattr(id, 'name')
  return attr !=# 'markdownCode' && attr !=# 'mkdCode' && attr !~# '.*Comment'
endfunction

function! MarkdownFoldOverride() abort
  let line = getline(v:lnum)

  if line =~# '^#\+ ' && s:NotCodeBlock(v:lnum)
    " return ">" . match(line, ' ')
    return ">1"
  endif

  let nextline = getline(v:lnum + 1)
  if (line =~ '^.\+$') && (nextline =~ '^=\+$') && s:NotCodeBlock(v:lnum + 1)
    return ">1"
  endif

  if (line =~ '^.\+$') && (nextline =~ '^-\+$') && s:NotCodeBlock(v:lnum + 1)
    " return ">2"
    return ">1"
  endif

  if line =~# '^\(    \)*- ' && s:NotCodeBlock(v:lnum)
    return ">" . ((match(line, '-') / 4) + 1)
  endif

  " return "="
  return "1"
endfunction

function! s:HashIndent(lnum) abort
  let hash_header = matchstr(getline(a:lnum), '^#\{1,6}')
  if len(hash_header)
    return hash_header
  else
    let nextline = getline(a:lnum + 1)
    if nextline =~# '^=\+\s*$'
      return '#'
    elseif nextline =~# '^-\+\s*$'
      return '##'
    endif
  endif
  return ''
endfunction

function! MarkdownFoldTextOverride() abort
  let hash_indent = s:HashIndent(v:foldstart)
  let title = substitute(getline(v:foldstart), '^#\+\s*', '', '')
  let foldsize = (v:foldend - v:foldstart + 1)
  let linecount = '['.foldsize.' lines]'
  if len(hash_indent) > 0
    let hash_indent = hash_indent.' '
  endif
  if len(title) > 0
    let title = title.' '
  endif
  return hash_indent.title.linecount
endfunction

if has("folding") && exists("g:markdown_folding_override")
  setlocal foldexpr=MarkdownFoldOverride()
  setlocal foldmethod=expr
  setlocal foldtext=MarkdownFoldTextOverride()
  let b:undo_ftplugin .= " foldexpr< foldmethod< foldtext<"
endif

" vim:set sw=2:
