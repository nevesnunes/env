#define _GNU_SOURCE
#define NO_RTLD_HIDDEN

#include <dlfcn.h>
#include <stdio.h>

#include <fts.h>
#include <ftw.h>
#include <glob.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <utime.h>

#ifndef _STAT_VER
#if defined(__aarch64__)
#define _STAT_VER 0
#elif defined(__x86_64__)
#define _STAT_VER 1
#else
#define _STAT_VER 3
#endif
#endif

const char *clean(const char *filename, const char *caller) {
    int new_len = sizeof(char) * (strlen(filename) * 2 + 1);
    char *new_filename = malloc(new_len);
    memset(new_filename, 0, new_len);

    char *strtok_filename = malloc(sizeof(char) * (strlen(filename) + 2));
    strcpy(strtok_filename, filename);

    if (strlen(filename) > 0 && filename[0] == '/') {
        strncat(new_filename, "/", 1);
    }

    int cleaned = 0;
    const char delims[] = {'/', '\0'};
    char *temp = strtok(strtok_filename, delims);
    while (temp != NULL) {
        int len = strlen(temp);
        strncat(new_filename, temp, len);

        if (!(strcmp(temp, ".") == 0 || strcmp(temp, "..") == 0) &&
            temp[len - 1] == '.') {
            cleaned = 1;
            strncat(new_filename, "_", 1);
        }

        temp = strtok(NULL, delims);
        if (temp != NULL) {
            strncat(new_filename, "/", 1);
        }
    }

    if (cleaned) {
        printf(
            "%s: Cleaned filename: %s => %s\n", caller, filename, new_filename);
    }

    return new_filename;
}

int main() {
    printf("%s\n", clean("/foo/bar", "1"));
    printf("%s\n", clean("/", "1"));
    printf("%s\n", clean("//foo/", "1"));
    printf("%s\n", clean("foo", "1"));
    printf("%s\n", clean(".", "1"));
    printf("%s\n", clean("..", "1"));
    printf("%s\n", clean("/./.", "1"));
    printf("%s\n", clean(".foo", "1"));
    printf("%s\n", clean("foo.\x01", "1"));
    printf("%s\n", clean("foo.", "1"));
    return 0;
}
