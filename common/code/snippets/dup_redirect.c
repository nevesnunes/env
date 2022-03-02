#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void some_func() {
    printf("This gets written to file.\n");
    fflush(stdout);
}

void redirect_stdout(void (*some_func)(void), char *file) {
    printf("Preparing to redirect to file:\n");
    fflush(stdout);
    // sys has three streams (0)stdin (1)stdout (2)stderr
    // use dup to store the stdout for restoration later:
    int saved_stdout = dup(1);
    int fw = open(file, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    // checks for open failure and cleans up resources / prints errors if so
    if (fw < 0) {
        printf("Failed to open %s.\n", file);
        perror("Error: ");
        if (close(saved_stdout) != 0) {
            perror("Error: ");
        }
        return;
    }
    dup2(fw, 1); // use 1 as it is the integer assigned to stdout
    some_func();
    if (close(fw) != 0) { // checks for bad file descriptor
        perror("Error: ");
    }
    dup2(saved_stdout, 1);
    if (close(saved_stdout) != 0) { // checks for bad file descriptor
        perror("Error: ");
    }
}

int main(void) {
    char filename[] = "stdout_content.txt";
    redirect_stdout(some_func, filename);
    printf("Stdout now back to terminal output.\n");
    return 0;
}
