#!/usr/bin/env python3

CODE = {
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
}

# https://norvig.com/mayzner.html
# http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/
letter_frequencies = {
    "E": 12.49,
    "T": 9.28,
    "A": 8.04,
    "O": 7.64,
    "I": 7.57,
    "N": 7.23,
    "S": 6.51,
    "R": 6.28,
    "H": 5.05,
    "L": 4.07,
    "D": 3.82,
    "C": 3.34,
    "U": 2.73,
    "M": 2.51,
    "F": 2.40,
    "P": 2.14,
    "G": 1.87,
    "W": 1.68,
    "Y": 1.66,
    "B": 1.48,
    "V": 1.05,
    "K": 0.54,
    "X": 0.23,
    "J": 0.16,
    "Q": 0.12,
    "Z": 0.09,
}

morse_chars_frequencies = {}
for lf in letter_frequencies.keys():
    code = CODE[lf]
    morse_chars = {}
    for c in code:
        if c not in morse_chars:
            morse_chars[c] = 0
        morse_chars[c] += 1
    for c in morse_chars.keys():
        if c not in morse_chars_frequencies:
            morse_chars_frequencies[c] = 0
        morse_chars_frequencies[c] += letter_frequencies[lf] * (morse_chars[c] / len(code))
print(morse_chars_frequencies)
# {'.': 59.30666666666667, '-': 40.67333333333334}
