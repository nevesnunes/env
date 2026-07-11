#include <stdio.h>

int main(void)
{
    char *w = "?";
    switch (sizeof(void *)) {
    case 1: w = "8";  break;
    case 2: w = "16"; break;
    case 4: w = "32"; break;
    case 8: w = "64"; break;
    }

    char *b = "?";
    switch (*(char *)(int []){1}) {
    case 0: b = "big";    break;
    case 1: b = "little"; break;
    }

    printf("%s-bit, %s endian\n", w, b);
}
