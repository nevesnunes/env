#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

// Reference: https://rosettacode.org/wiki/Call_a_function_in_a_shared_library#C
// Compile: gcc dlsym.c -ldl

int main(int argc, char *argv[]) {
    void *plugin = dlopen(argv[1], RTLD_NOW);
    char *result = dlerror();
    if (result) {
        printf("dlopen(): %s\n", result);
        exit(1);
    }
    if ( plugin != NULL ) {
        char *sym = "init";
        void (*init)() = dlsym(plugin, sym);
        char *result = dlerror();
        if (result) {
            printf("dlsym() error when loading %s from %s: %s\n", sym, argv[1], result);
            exit(1);
        }
        init();
        dlclose(plugin);
    } else {
        printf("dlopen() returned null for %s\n", argv[1]);
        exit(1);
    }

    return 0;
}
