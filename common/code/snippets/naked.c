void my_write(int fd, const void *buf, int count);

asm
(
".global my_write                          \n\t"
"write:                                    \n\t"
"       pusha                              \n\t"
"       movl   $4, %eax                    \n\t"
"       movl   36(%esp), %ebx              \n\t"
"       movl   40(%esp), %ecx              \n\t"
"       movl   44(%esp), %edx              \n\t"
"       int    $0x80                       \n\t"
"       popa                               \n\t"
"       ret                                \n\t"
);

void _start()
{
    my_write(1, "hi\n", 3);
    my_write(1, "bye\n", 4);
}
