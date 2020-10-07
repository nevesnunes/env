" /!\ Too slow
function! s:NotCodeBlock(lnum) abort
  let matched_block_end = 0
  let end_i = max([1, v:lnum - g:markdown_minlines])
  for i in range(v:lnum, end_i, -1)
    let line = getline(i)
    if line =~ '^`\+'
      let attr = synIDattr(synID(i, 1, 1), 'name')
      if attr =~# 'mkdCodeEnd'
        matched_block_end = 1
      elseif attr =~# 'mkdCodeStart'
        return &matched_block_end == 1
      endif
    endif
  endfor

  let attr = synIDattr(synID(v:lnum, 1, 1), 'name')
  return attr !=# 'markdownCode' && attr !=# 'mkdCode'
endfunction
