#include <limits.h>
#include <stdlib.h>
#include <stdio.h>

__asm__(".symver realpath,realpath@GLIBC_2.2.5");
int main()
{
    const char* unresolved = "/lib64";
    char resolved[PATH_MAX+1];

    if(!realpath(unresolved, resolved))
        { return 1; }

    printf("%s\n", resolved);

    return 0;
}
