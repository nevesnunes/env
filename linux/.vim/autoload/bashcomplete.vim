function! bashcomplete#Init()
    if exists('g:bashcomplete#commands') == 0
        let g:bashcomplete#commands = system('bash -i -c "complete | sed \"s/.*\ //g\" | sort -u"')
        let g:bashcomplete#keywords = [ "function", "while", "until", "for", "done", "do", "case", "esac", "if", "then", "else", "elif", "fi" ]
    endif
endfun

function! bashcomplete#Complete(findstart, base)
    call bashcomplete#Init()

    if a:findstart
        let line = getline('.')
        let start = col('.') - 1
        while start > 0 && line[start - 1] =~ '\a'
            let start -= 1
        endwhile
        return start
    endif

    let res = []
    let candidates = split(g:bashcomplete#commands) + g:bashcomplete#keywords
    for m in candidates
        if m =~ '^' . a:base
            call add(res, m)
        endif
    endfor
    return res
endfun
