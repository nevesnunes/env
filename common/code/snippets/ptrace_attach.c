/* attach */
ptrace(PTRACE_ATTACH, pid, 0, 0);

/* wait for the attach request to complete */
waitpid(pid, NULL, 0);

/* set ptrace options */
ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_SYSVGOOD);

/* resume ptrace execution */
ptrace(PTRACE_SYSCALL, pid, 0, 0);

while (1) {
    int status = 0;
    int pid = waitpid(pid, &status, 0);

    /* handle ptrace events */
    /*  ... */

    /* resume tracee execution */
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
}
