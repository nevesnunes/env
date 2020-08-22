/*
 * benjamin.poirier@gmail.com
 *
 * A wrapper around mprotect(2)
 * build with:
 * cc -Wall -g  -ldl  wrapper.c   -shared -fPIC -o wrapper.so
 *
 * run with:
 * LD_PRELOAD=./somepath/wrapper.so ./otherprogram
 *
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

int (*fp)(void *, size_t, int);

void __attribute__((constructor)) init(void) {
    fp = dlsym(RTLD_NEXT, "mprotect");
}

/* Change the memory protection of the region starting at ADDR and
   extending LEN bytes to PROT.  Returns 0 if successful, -1 for errors
   (and sets errno).  */
int mprotect(void *__addr, size_t __len, int __prot) {
    void *buffer[40];
    char **strings;
    int retval;
    int i;

    printf("Calling mprotect(%p, %zd, %d)\n", __addr, __len, __prot);

    retval = backtrace(buffer, ARRAY_SIZE(buffer));
    printf("    Backtrace (%d entries):\n", retval);
    strings = backtrace_symbols(buffer, retval);
    for (i = 0; i < retval; i++) {
        printf("        %s\n", strings[i]);
    }
    free(strings);

    return fp(__addr, __len, __prot);
}
