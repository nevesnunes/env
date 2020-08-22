#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

char b[4] = "ABCD";
int main(void) {
    int a = 0;
    for (size_t i = 0; i < 100; i++) {
        if (a < 10) {
            a++;
            b[3]++;
        } else {
            a += 2;
        }
    }
    printf("%d\n", a); // 190
    printf("%s\n", b); // ABCN

    return 0;
}
