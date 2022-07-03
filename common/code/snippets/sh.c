#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CMD_LEN 1024

char *sh_skipwhite(char *s) {
    while (isspace(*s)) {
        ++s;
    }

    return s;
}

void sh_split(char *cmd, char **args) {
    cmd = sh_skipwhite(cmd);
    char *next = strchr(cmd, ' ');
    int i = 0;

    while (next != NULL) {
        next[0] = '\0';
        args[i] = cmd;
        ++i;
        cmd = sh_skipwhite(next + 1);
        next = strchr(cmd, ' ');
    }

    if (cmd[0] != '\0') {
        args[i] = cmd;
        next = strchr(cmd, '\n');
        next[0] = '\0';
        ++i;
    }

    args[i] = NULL;
}

void sh_run(char *cmd, char **args) {
    sh_split(cmd, args);
    if (args[0] != NULL) {
        printf("%s %s\n", cmd, args[1]);
    }
}

void sh_loop() {
    char line[CMD_LEN];
    char *args[CMD_LEN / 2];
    while (1) {
        printf("> ");
        fflush(NULL);

        if (!fgets(line, CMD_LEN, stdin)) {
            return;
        }

        sh_run(line, args);
    }
}

int main() {
    sh_loop();

    return 0;
}
