/*-----------------------------------------------------------------------------
 *
 *        GENERATES THE SEQUENCE FOR CD SCRAMBLER
 *        =============================================
 *
 * build 0x001 @ 07.06.2003
------------------------------------------------------------------------------*/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

const size_t SYNC_BLOCK_LEN = 12;
uint16_t ScramblerTable[1170];

void RawScrambleSector(char *raw_sector) {
    uint16_t *p = (uint16_t *)(raw_sector + 12);
    for (size_t a = 0; a < 2340 / 4; a++) {
        p[a] ^= ScramblerTable[a];
    }
}

void RawScramble(char *data) {
    uint16_t *p = (uint16_t *)(data);
    for (size_t a = 0; a < SYNC_BLOCK_LEN / 2; a++) {
        p[a] ^= ScramblerTable[a + 2];
    }
}

// Check fragment of the real scrambling sequence for checking the program
// -----------------------------------------------------------------------
// 0x8001,0x6000,0x2800,0x1e00,0x0880,0x0660,0x02a8,0x81fe,0x6080,0x2860,0x1e28,
// 0x889e,0x6668,0xaaae,0x7ffc,0xe001,0x4800,0x3600,0x1680,0x0ee0,0x04c8,0x8356,
// 0xe17e,0x48e0,0x3648,0x96b6,0xeef6,0xccc6,0xd552,0x9ffd,0xa801,0x7e00,0x2080,
void InitScramblerTable() {
    int tmp;
    uint16_t reg = 0x8001; // The first element of the scrambling sequence
    ScramblerTable[0] = reg;
    for (size_t a = 1; a < 1170 /* The scrambled sector part length in words*/; a++) {
        // Modulo-2 addition with shift
        tmp = reg >> 1;
        tmp = reg ^ tmp;
        reg = tmp >> 1;

        // Processing polynomial x^15+x+1, e.g., 1<<15 + 1<<1 + 1<<0
        if (reg & 1 << 1)
            reg = reg ^ (1 << 15);
        if (reg & 1 << 0)
            reg = reg ^ ((1 << 15) | (1 << 14));

        ScramblerTable[a] = reg;
    }
}

int main() {
    InitScramblerTable();

    char data[] = {"\x00\xD7\xFF\xE1\x7F\xF7\x9F\xF9\x57\xFD\x01\x81"};
    RawScramble(data);
    for (size_t a = 0; a < SYNC_BLOCK_LEN; a++) {
        printf("%02hhx ", data[a]);
    }

    return 0;
}
