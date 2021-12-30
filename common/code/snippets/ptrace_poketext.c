#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * References:
 * - http://omeranson.github.io/blog/2018/04/08/ptrace-magic-redirect-a-running-programme
 * - http://www.linuxjournal.com/article/6100?page=0,1
 * - https://gist.github.com/caiorss/339b00fc8ab1b3d1d46ed9167ccbaeeb
 * - https://gist.github.com/303248153/30d72a91e116240251af3e7a5ff71d05
 * - https://gist.github.com/caiorss/339b00fc8ab1b3d1d46ed9167ccbaeeb
 */

void print_word(long res) {
    char *datap = (char *)&res;
    if (res == -1)
        fprintf(stderr, "PTRACE_PEEKTEXT errno=%d (%s)\n", errno, strerror(errno));
    else
        printf("0x%02X%02X%02X%02X\n", datap[0], datap[1], datap[2], datap[3]);
}

int main(int argc, char *argv[]) {
    pid_t pid = (pid_t)strtoll(argv[1], NULL, 0);

    long res;
    res = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (res != 0)
        fprintf(stderr, "PTRACE_ATTACH errno=%d (%s)\n", errno, strerror(errno));

    int status;
    waitpid(pid, &status, 0);

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    printf("rip: 0x%llX\n", regs.rip);

    long data = 0xAABBCCDD;
    res = ptrace(PTRACE_PEEKTEXT, pid, (void *)regs.rip, NULL);
    print_word(res);
    res = ptrace(PTRACE_POKETEXT, pid, (void *)regs.rip, (void *)&data);
    if (res != 0)
        fprintf(stderr, "PTRACE_POKETEXT errno=%d (%s)\n", errno, strerror(errno));
    res = ptrace(PTRACE_PEEKTEXT, pid, (void *)regs.rip, NULL);
    print_word(res);

    return 0;
}
