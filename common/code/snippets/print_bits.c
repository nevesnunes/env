#include <stdio.h>
#include <stdlib.h>

unsigned char *char_bits(unsigned char buf[], unsigned char num) {
    unsigned char *pbuf = buf;
    unsigned char size = sizeof(unsigned char);
    int i;
    for (i = size * 8 - 1; i >= 0; i--) {
        sprintf(pbuf, "%u", (num >> i) & 1);
        pbuf++;
    }
    return buf;
}

int main() {
    unsigned char buf[8 + 1];
    buf[8] = '\0';
    char line[0xff];
    while (fgets(line, sizeof(line), stdin)) {
        printf("%s\n", char_bits(buf, (char)atoi(line)));
    }
}
