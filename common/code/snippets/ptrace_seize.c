ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_SYSVGOOD);
ptrace(PTRACE_INTERRUPT, pid, 0, 0);
ptrace(PTRACE_SYSCALL, pid, 0, 0);

while (1) {
    int status = 0;
    int pid = waitpid(pid, &status, 0);
    /* ... */
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
}
