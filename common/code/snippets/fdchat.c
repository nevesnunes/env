// Exfiltrate via file descriptors.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void send(uint8_t msg) {
    // Encode each bit as a file descriptor in range 10..17.
    for (int i = 0; i < 8; i++) {
        close(10 + i);
        if ((msg >> i) & 1) {
            dup2(0, 10 + i);
        }
    }

    // Ready to be delivered.
    dup2(0, 18);
}

void recv(int pid) {
    char fd[32];
    sprintf(fd, "/proc/%d/fd/", pid);
    if (access(fd, F_OK)) {
        exit(EXIT_FAILURE);
    }

    // Wait for msg to be ready.
    sprintf(fd, "/proc/%d/fd/18", pid);
    while (access(fd, F_OK)) {
        usleep(500000);
    }

    uint8_t msg = 0;
    for (int i = 0; i < 8; i++) {
        sprintf(fd, "/proc/%d/fd/%d", pid, 10 + i);
        if (!access(fd, F_OK)) {
            msg |= (1 << i);
        }
    }
    printf("msg: 0x%02x\n", msg);
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        printf("my pid: %d\n", getpid());
        send(0x67);
        printf("ctrl-c me :3\n");
        pause();
    } else if (argc == 2) {
        recv(atoi(argv[1]));
    }

    return 0;
}
