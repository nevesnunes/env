#!/usr/bin/env python3

import collections


def make_columns(text, key_length):
    """ Returns columns of length = key_length for text"""
    blocks = []

    # Divide ciphertext into blocks of length = key_length
    for i in xrange(0, len(text) / key_length):
        blocks.append(list(text[key_length * i : key_length * i + key_length]))

    # Create list: [[blocks[0][0], blocks[0][1], ...], [blocks[1][0], blocks[1][1], ...]]
    columns = map(list, zip(*blocks))

    # What about remaining text that doesn't fit into one block?
    if len(text) % key_length:
        remaining = text[key_length * (len(text) / key_length)]
        for i in xrange(len(remaining)):
            columns[i].append(remaining[i])

    return columns


columns = char_distribution(ciphertext, 9)


def chi_squared(ciphertext, freqs):
    d = collections.Counter(ciphertext)
    res = []

    for k, v in freqs.iteritems():
        c = 0
        decrypted = []

        for i in ciphertext:
            # Do the XOR operation
            decrypted.append(chr(k ^ ord(i)))

        for l in decrypted:
            # Apply the Chi squared test:
            #
            #   sum = 0
            #   for every character c in s do:
            #         expected_count = length(ciphertext) * frequency_table(c)
            #         real_count = <number of occurences of c in ciphertext>
            #         sum += (real_count - expected_count) ** 2 / expected_count
            #
            expected_count = float(len(ciphertext) * float(freqs[ord(l)]))
            real_count = float(d[l])

            # Avoid division by 0
            if expected_count > 0:
                c += (real_count - expected_count ** 2) / expected_count

        res.append(c)

    return res


res = chi_squared(columns[1], percent_freqs)
print(chr(res.index(min(res))))

key = ""

for i in columns:
    res = chi_squared(i, percent_freqs)
    key += chr(res.index(min(res)))
print(key)
