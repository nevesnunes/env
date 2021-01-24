# +


- [Quipquip](https://quipqiup.com/): subsituition cipher
- [Decode.fr](https://www.dcode.fr/): old school ciphers
- [CSCBE2019 - Rosetta](https://renaud11232.github.io/ctf/CSCBE2019/Finals/rosetta/): multiple ciphers / alphabets / languages / fonts

- [CyberChef](https://gchq.github.io/CyberChef/): magic mode
    - [Enigma Simulation in Javascript/HTML](http://people.physik.hu-berlin.de/~palloks/js/enigma/index_en.html)
- [kt.gy tools](https://kt.gy/tools.html): decode string
    - https://github.com/OpenToAllCTF/Tips#crypto
- [GitHub \- bwall/HashPump: A tool to exploit the hash length extension attack in various hashing algorithms](https://github.com/bwall/HashPump)
    - [GitHub \- stephenbradshaw/hlextend: Pure Python hash length extension module](https://github.com/stephenbradshaw/hlextend)
- [GitHub \- mwielgoszewski/python\-paddingoracle: A portable, padding oracle exploit API](https://github.com/mwielgoszewski/python-paddingoracle)
- [AES Encryption \- Easily encrypt or decrypt strings or files](http://aes.online-domain-tools.com/)
- [The On\-Line Encyclopedia of Integer Sequences \(OEIS\)](https://oeis.org)
- https://github.com/apsdehal/awesome-ctf#crypto

```python
gmpy2.isqrt(B * N // A)

hashlib.md5().update(b'foo').hexdigest()

# ~/code/guides/ctf/TFNS---writeups/2020-09-25-BalCCon/cryptosh/cryptsh.py
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad, unpad

# ~/code/guides/ctf/TFNS---writeups/2020-09-25-BalCCon/do_u_have_knowledge/server.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
cipher = Cipher(algorithms.AES(b'1234567890123456'), modes.ECB(), backend = default_backend())
```

- Hill cipher - https://github.com/t3rmin0x/CTF-Writeups/tree/master/DarkCTF/Crypto/Embrace%20the%20Climb#embrace-the-climb-
- https://en.wikipedia.org/wiki/Feistel_cipher
- indistinguishability under chosen-plaintext attack (IND-CPA)

# hashing

- [Hash Analyzer \- TunnelsUP](https://www.tunnelsup.com/hash-analyzer/)
- [CrackStation \- Online Password Hash Cracking \- MD5, SHA1, Linux, Rainbow Tables, etc\.](https://crackstation.net/)
- POSIX user account passwords (`/etc/passwd, /etc/shadow`)
    - https://en.wikipedia.org/wiki/Crypt_(C)#Key_derivation_functions_supported_by_crypt
- md5 with salt
    - `hashcat -m 20 -a 0 -o cracked.txt crackme.txt /usr/share/wordlists/rockyou.txt --force" # $hash:$salt`
- hs256 = hmac sha256

### similarity

```bash
ssdeep -s foo > fuzzy.db
ssdeep -s -a -m fuzzy.db foo bar
# foo matches fuzzy.db:foo (100)
# bar matches fuzzy.db:foo (0)
```

- [GitHub \- sdhash/sdhash: similarity digest hashing tool](https://github.com/sdhash/sdhash)
- [GitHub \- ssdeep\-project/ssdeep: Fuzzy hashing API and fuzzy hashing tool](https://github.com/ssdeep-project/ssdeep)

### patterns

```bash
md5sum <() # d41d8cd98f00b204e9800998ecf8427e
sha1sum <() # da39a3ee5e6b4b0d3255bfef95601890afd80709
sha256sum <() # e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### search space estimation

```javascript
// [GRC's \| Password Haystacks: How Well Hidden is Your Needle?](https://www.grc.com/haystack.htm)
function grc(len) {
  if(len < 1) {
    return 0;
  } else if (len == 1) {
    return window.charsetsize;
  }
  return Math.pow(window.charsetsize, len - 1) + grc(len - 1);
}
console.log(grc(64));
// 110
```

```python
>>> len(list(permutations([i for i in range(0,10)], 2)))
90
>>> int(factorial(10)/factorial(10-2))
90
>>> int(factorial(36)/factorial(36-8))
1220096908800
# MAC address
>>> int(factorial(16)/factorial(16-12))
871782912000
```

# rsa

- [GitHub \- Ganapati/RsaCtfTool: RSA attack tool \(mainly for ctf\) \- retreive private key from weak public key and/or uncipher data](https://github.com/Ganapati/RsaCtfTool)
- Factorizing big integers - http://factordb.com/

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
- Guessing key length + values by decrypted output byte range
    - ~/code/guides/ctf/grayrepo/2017_flareon/flare10_shellphp/README.md

# frequency analysis

- key length: ~/code/snippets/ctf/crypto/kasiski.py
- letter frequency: ~/code/snippets/ctf/crypto/frequency_analysis.py
- decrypt letters: ~/code/snippets/ctf/crypto/chi_squared.py

http://blog.dornea.nu/2016/10/29/ringzer0-ctf-javascript-challenges/#207f46edd62ccf43b49d59d48df5c867

# pseudo random number generator (PRNG)

- known seed => bruteforce generated values
    ```python
    import random, string
    random.seed(1601405147.6444)
    alphabet = list(string.ascii_lowercase + string.digits)
    print("".join([random.choice(alphabet) for _ in range(32)]))
    # mq4fyjs6rlo5jjotg3xiwr76z8hm4chi
    ```
    - [CTFtime\.org / BalCCon2k20 CTF / Two Sides of a Coin / Writeup](https://ctftime.org/writeup/23792)
        - ~/share/ctf/BalCCon2k20/two-sides-of-a-coin-solutions/
- small n-periodic
    - https://github.com/fab1ano/tasteless-ctf-20/tree/master/babychaos
- https://ctftime.org/writeups?tags=prng&hidden-tags=prng
- https://www.cryptomathic.com/news-events/blog/generating-cryptographic-keys-with-random-number-generators-prng
- ~/Downloads/Not_So_Random_-_Exploiting_Unsafe_Random_Number_Generator_Use.pdf

### mersenne twister

- given known implementation, optionally seed range, and multiple generated values, then bruteforce seed
    - [GitHub \- altf4/untwister: Seed recovery tool for PRNGs](https://github.com/altf4/untwister)
    - [GitHub \- kmyk/mersenne\-twister\-predictor: Predict MT19937 PRNG, from preceding 624 generated numbers\. There is a specialization for the &quot;random&quot; of Python standard library\.](https://github.com/kmyk/mersenne-twister-predictor)
    - https://dragonsector.pl/docs/0ctf2016_writeups.pdf
    - https://sasdf.github.io/ctf/tasks/2019/BalsnCTF/crypto/unpredictable/

### LSFR

[GitHub \- bozhu/BMA: Berlekamp\-Massey algorithm](https://github.com/bozhu/BMA)

# one-time pad

https://medium.com/hackstreetboys/securinets-ctf-quals-2019-useless-admin-crypto-4e2685452fec

# electronic color book (AES-ECB)

- https://crypto.stackexchange.com/questions/31019/if-you-encrypt-an-image-aes-is-it-still-an-image-and-can-you-view-it
    - https://blog.filippo.io/the-ecb-penguin/
    - https://crypto.stackexchange.com/questions/63145/variation-on-the-ecb-penguin-problem
    ```bash
    head -n 4 Tux.ppm > header.txt
    tail -n +5 Tux.ppm > body.bin
    openssl enc -aes-128-ecb -nosalt -pass pass:"ANNA" -in body.bin -out body.ecb.bin
    cat header.txt body.ecb.bin > Tux.ecb.ppm
    ```

# mitigations

|Language|CSPRNG|
|---|---|
|.NET|`RNGCryptoServerProvider()`|
|Java|`java.security.SecureRandom()`|
|JavaScript (Node.js)|`crypto.RandomBytes()`|
|PHP|`random_bytes()`|
|Python|`random.SystemRandom()`|

# Correlation Power Analysis (CPA) / Differential Fault Analysis (DFA) / White-Box Cryptography

- [GitHub \- SideChannelMarvels/Daredevil: A tool to perform \(higher\-order\) correlation power analysis attacks \(CPA\)\.](https://github.com/SideChannelMarvels/Daredevil)

- https://atorralba.github.io/RHme3-Quals-Whitebox/
- https://blog.quarkslab.com/differential-fault-analysis-on-white-box-aes-implementations.html
- https://www.limited-entropy.com/crypto-series-dfa/
- https://www.ledger.com/ctf-complete-hw-bounty-still-ongoing-2-337-btc/
    > induce faults using GDB during the computation, retrieve the faulty result and then execute AES DFA (Differential Fault Analysis)

# case studies

- https://nakedsecurity.sophos.com/2013/07/09/anatomy-of-a-pseudorandom-number-generator-visualising-cryptocats-buggy-prng/
    - https://tobtu.com/decryptocat.php
- https://www.pcg-random.org/posts/visualizing-the-heart-of-some-prngs.html
    - [ ] reproduce vizs

- https://medium.com/@betable/tifu-by-using-math-random-f1c308c4fd9d
    - https://v8.dev/blog/math-random
- https://blog.malwarebytes.com/threat-analysis/2018/01/scarab-ransomware-new-variant-changes-tactics/

### hashing

- identifying files in raw dumps - 1. hash the first k bytes of all known files; 2. take offsets matching a given sequence, hash the first k bytes at those offsets, then compare with known set
    - https://behind.pretix.eu/2020/11/28/undelete-flv-file/
- discovering bugs due to unexpected magic byte sequences
    > Mostly just IDA, I managed to get a trace of lsass while CryptUnprotectData() was working and failing, then got a lucky break - I saw it derive a key from a byte sequence I knew (da 39 a3 ee...), that's the SHA-1 of the empty string! That led me to credentials being clobbered
    - https://twitter.com/taviso/status/1310619801606184960


