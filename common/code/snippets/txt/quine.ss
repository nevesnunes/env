; Quine example in Dr. Scheme
;
; The main idea is to define a function that when given itself as 
; an argument repeats itself. We can get an idea if we look at the 
; identity function.

((lambda (x) x) 'a)
((lambda (x) x) 5)
((lambda (x) x) "a string")
((lambda (x) x) '(a b c))

; If applied to itself, we start to get the idea of what is 
; required if the function is a quoted version of itself:

((lambda (x) x) '(lambda (x) x))
         
; By the way, the identity lambda with its argument 
; NOT in parenthesis turns its arguments into a list
; i.e., (lambda x x) == (list x)

((lambda x x) 'a 'b 'c)

; We can start to see how to define a function to duplicate itself
; like this:

((lambda (x) x x) '(lambda (x) x x))

; But in the case above the body of the leftmost lambda
; gets evaluated. We need to somehow "cancel" the evaluation
; and just treat the argument like a value. What if we
; "double" quote it?

((lambda (x) x x) ''(lambda (x) x x))

; Now we see what is happening. The quote is being removed
; as part of the evaluation. We can try "unquoting" the
; argument. To use unquote, we have to include it in a
; quote or quasiquote since (unqoute x) is illegal by itself

((lambda (x) (quasiquote ((unquote x) x))) 
 '(lambda (x) (quasiquote ((unquote x) x))))

; Almost there! We got the first x in the body doing the right 
; thing, we need to get the second x to be the same thing.

((lambda (x) (quasiquote ((unquote x) '(unquote x))))
 '(lambda (x) (quasiquote ((unquote x) '(unquote x)))) )

; Which with some syntactic sugar becomes:

((lambda(x) `(,x ',x)) '(lambda(x) `(,x ',x)))  ; 46 characters!

; Here's another way to do it

((lambda (x) (list x (list 'quote x)))
 (quote (lambda (x) (list x (list 'quote x)))))


; HOMEWORK: expriment with quasiquote, quote and unqoute to figure 
; out how this works!

(define x 5)
x
(quote x)
(quote (quote x))
;(unquote x)
(quote (unquote x))
(quasiquote x)
(quasiquote (quote x))
(quasiquote (unquote x))
(quasiquote (unquote (quote x)))
(lambda (x) x x)
(quote (lambda (x) x x))
(quote (unquote (lambda (x) x x)))
(quasiquote (quote (lambda (x) x x)))


