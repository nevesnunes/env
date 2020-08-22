#include <dlfcn.h>
#include <stdio.h>

int main() {
    void *plugin = dlopen("foo.so", RTLD_NOW);
    void (*init)() = dlsym(plugin, "init");
    char *result = dlerror();
    if (result) {
        printf("Cannot find init in %s: %s", "foo", result);
    }
    init();
    dlclose(plugin);

    return 0;
}
