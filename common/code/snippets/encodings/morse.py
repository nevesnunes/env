#!/usr/bin/env python3

import sys

CODE = {
    'A': '.-',     'B': '-...',   'C': '-.-.',
    'D': '-..',    'E': '.',      'F': '..-.',
    'G': '--.',    'H': '....',   'I': '..',
    'J': '.---',   'K': '-.-',    'L': '.-..',
    'M': '--',     'N': '-.',     'O': '---',
    'P': '.--.',   'Q': '--.-',   'R': '.-.',
    'S': '...',    'T': '-',      'U': '..-',
    'V': '...-',   'W': '.--',    'X': '-..-',
    'Y': '-.--',   'Z': '--..',

    '0': '-----',  '1': '.----',  '2': '..---',
    '3': '...--',  '4': '....-',  '5': '.....',
    '6': '-....',  '7': '--...',  '8': '---..',
    '9': '----.'
}

CODE_REVERSED = {value: key for key, value in CODE.items()}


def to_morse(s):
    return " ".join(CODE.get(i.upper()) for i in s)


def from_morse(s):
    return ''.join(CODE_REVERSED.get(i, '_') for i in s.split(' '))

morse = ""
for i in sys.stdin.readlines():
    i = float(i)
    if i < 0.25:
        morse += "."
    elif i > 0.5 and i < 1:
        morse += "-"
    else:
        morse += " "
print(morse)
print(from_morse(morse))
