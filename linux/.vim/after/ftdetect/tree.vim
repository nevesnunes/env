function FoldText()
  let line = getline(v:foldstart)
  let sub = substitute(line, '/\*\|\*/\|{{{\d\=', '', 'g')
  return sub . v:folddashes
endfunction
autocmd FileType tree setlocal foldmethod=expr foldtext=FoldText()
