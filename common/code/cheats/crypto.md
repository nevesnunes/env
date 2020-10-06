# +

https://github.com/apsdehal/awesome-ctf#crypto

- [Quipquip](https://quipqiup.com/): subsituition cipher
- [Decode.fr](https://www.dcode.fr/): old school ciphers
- [CyberChef](https://gchq.github.io/CyberChef/): magic mode
- [kt.gy tools](https://kt.gy/tools.html): decode string 
    - https://github.com/OpenToAllCTF/Tips#crypto

- [The On\-Line Encyclopedia of Integer Sequences \(OEIS\)](https://oeis.org)

```python
gmpy2.isqrt(B * N // A)
```

# hashing

hs256 = hmac sha256

# rsa

http://factordb.com/

# xor

https://wiremask.eu/tools/xor-cracker/

- On length(known_prefix) >= length(key), full decryption is direct
    ```bash
    ~/code/snippets/ctf/crypto/xor_decrypt.py 'darkCTF{' <(printf '%s' '5552415c2b3525105a4657071b3e0b5f494b034515' | xxd -r -p)
    # 1337hack>'%lXjM$-*q.V
    ~/code/snippets/ctf/crypto/xor_decrypt.py '1337hack' <(printf '%s' '5552415c2b3525105a4657071b3e0b5f494b034515' | xxd -r -p)
    # darkCTF{kud0s_h4xx0r}
    ~/code/snippets/ctf/crypto/xor_decrypt.py 'darkCTF{kud0s_h4xx0r}' <(printf '%s' '5552415c2b3525105a4657071b3e0b5f494b034515' | xxd -r -p)
    # 1337hack1337hack1337h
    ```
- Split message into aligned sequences, count frequencies of chars foreach column, take most frequent char and xor with expected most frequent char (e.g. `_`) to obtain key
    - Alterntive: xortool
    - [CTFtime\.org / BalCCon2k20 CTF / Xoared / Writeup](https://ctftime.org/writeup/23906)
- n-periodic prng
    - https://github.com/fab1ano/tasteless-ctf-20/tree/master/babychaos


