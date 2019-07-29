swapped = ((mychar >> 4) & 0x0f) | ((mychar << 4) & 0xf0);

//mychar = 0xA1 ---> 10100001
//swapped = 0x1A ----> 00011010   

and that's how you swap the upper and lower nibbles in a byte.

This is equivalent to SWAPF (PIC) / SWAP (AVR) for those coming from assembly

https://github.com/python-pillow/Pillow/issues/2622
