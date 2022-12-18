.set noreorder

.text

.thumb_func
.balign 2
.global __start
.type __start, %function
__start:
    push { r4, lr }
    mov r0, #0x0
    bl foo
    mov r0, #0x0
    pop { r4 }
    pop { r1 }
    bx r1

.section ".text:foo"
.thumb_func
.balign 2
foo:
    nop

@ vim:ft=armv4
