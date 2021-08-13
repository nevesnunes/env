global _start
section .data
    fn:  db  '/etc/passwd',0

section .bss

section .text
_start:
    ; open the file
    xor rax,rax
    add al, 2
    lea rdi, [fn]
    xor rsi, rsi
    syscall

    ; read the file, use some area
    ; in the stack to store the contents
    mov rdi, rax
    sub sp, 0xfff
    lea rsi, [rsp]
    xor rdx, rdx
    mov dx, 0x200
    xor rax, rax
    syscall

    ; write to stdout
    xor rdi, rdi
    add dil, 1
    mov rdx, rax
    xor rax, rax
    add al,1
    syscall
    ; exit
    xor rax,rax
    add al, 60
    syscall
