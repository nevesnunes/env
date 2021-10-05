# +

- [Sage Cell Server](https://sagecell.sagemath.org/)
- [SageMath Documentation ](https://doc.sagemath.org/)
- [GitHub \- p4\-team/crypto\-commons: Small python module for common CTF crypto functions](https://github.com/p4-team/crypto-commons)

- [Quipquip](https://quipqiup.com/): substitution cipher
- [Substitution Solver \- www\.guballa\.de](https://guballa.de/substitution-solver): substitution cipher
- [Decode.fr](https://www.dcode.fr/): old school ciphers
- [Modular conversion, encoding and encryption online — Cryptii](https://cryptii.com/): enigma
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
    - [GitHub \- ckrause/loda: LODA is an assembly language, a computational model and a tool for mining integer sequence programs\.](https://github.com/ckrause/loda)
- https://github.com/apsdehal/awesome-ctf#crypto

- [GitHub \- ashutosh1206/Crypton: Library consisting of explanation and implementation of all the existing attacks on various Encryption Systems, Digital Signatures, Key Exchange, Authentication methods along with example challenges from CTFs](https://github.com/ashutosh1206/Crypton)
- https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html
- https://sockpuppet.org/blog/2013/07/22/applied-practical-cryptography/
- https://cryptohack.org/
- https://cryptopals.com/

- https://www.mersenneforum.org/index.php

```python
import gmpy2
gmpy2.get_context().precision = 200000
m = gmpy2.root(c, 3)

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

- id
    - https://github.com/HashPals/Name-That-Hash
    - https://github.com/noraj/haiti
    - [Hash Analyzer \- TunnelsUP](https://www.tunnelsup.com/hash-analyzer/)
- [CrackStation \- Online Password Hash Cracking \- MD5, SHA1, Linux, Rainbow Tables, etc\.](https://crackstation.net/)
- https://github.com/HashPals/Search-That-Hash/blob/main/search_that_hash/cracker/online_mod/online.py
    - MD5, SHA
        - https://hashtoolkit.com/decrypt-hash/?hash=
        - https://md5decrypt.net/Api/api.php?hash=
    - LM, NTLM
        - http://rainbowtables.it64.com
        - https://cracker.okx.ch:443
    - MySQL
        - https://www.cmd5.org:443
- POSIX user account passwords (`/etc/passwd, /etc/shadow`)
    - ./misc.md#crypt
- md5 with salt
    - `hashcat -m 20 -a 0 -o cracked.txt crackme.txt /usr/share/wordlists/rockyou.txt --force" # $hash:$salt`
- [The MD5 Message\-Digest Algorithm](https://tools.ietf.org/html/rfc1321)

### HMAC

- hs256 = hmac sha256

- Given `AES_CTR(SHA1(msg), KEY)` (AES keystream unchanged):
    - length extension
    - hmac value calculation: `mac_evil = mac_good ^ sha1(msg_good) ^ sha1(msg_evil)`

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

### bruteforcing search space estimation

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

- [Brute forcing device passwords](https://cybergibbons.com/reverse-engineering-2/brute-forcing-device-passwords/)

### checksums

- [GitHub \- 8051Enthusiast/delsum: A reverse engineer&\#39;s checksum toolbox](https://github.com/8051Enthusiast/delsum)

# rsa

- [GitHub \- Ganapati/RsaCtfTool: RSA attack tool \(mainly for ctf\) \- retreive private key from weak public key and/or uncipher data](https://github.com/Ganapati/RsaCtfTool)
- Factorizing big integers - http://factordb.com/

```python
from Crypto.Util.number import getStrongPrime

f = b"[REDACTED]"
m = int.from_bytes(f, "big")
p = getStrongPrime(512)
q = getStrongPrime(512)
n = p * q
e = 65537

# https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Encryption
c = pow(m, e, n)

# https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Decryption
d = pow(e, -1, (p - 1) * (q - 1))  # modinv(e, phi(modulus))
m = pow(c, d, n)
```

- From public key: take modulus = `n`
    - `openssl rsa -inform PEM -pubin -in public.key -text -noout`
    - https://github.com/VulnHub/ctf-writeups/blob/master/2015/eko-party-pre-ctf/rsa-2070.md
- Small `e`: take cube root of `c`
    - https://github.com/shiltemann/CTF-writeups-public/blob/master/PicoCTF_2018/writeup.md#cryptography-250-safe-rsa
- `n = p`
    - https://en.wikipedia.org/wiki/Euler%27s_totient_function
    ```python
    phi(N) = p - 1
    d = modinv(e, p-1)
    ```
- Coppersmith's short pad + Franklin-Reiter related-message
    - univariate polynomial
        - sage: `small_roots()`
        - [CTFtime\.org / PlaidCTF 2020 / dyrpto / Writeup](https://ctftime.org/writeup/21175)
        - [PapaRSA \(250\) &\#xB7; Hackademia Writeups](https://hgarrereyn.gitbooks.io/th3g3ntl3man-ctf-writeups/content/2017/UIUCTF/problems/Cryptography/papaRSA/)
    - bivariate polynomial
        - [GitHub \- ubuntor/coppersmith\-algorithm: Implements Coron&\#39;s simplification of Coppersmith&\#39;s algorithm](https://github.com/ubuntor/coppersmith-algorithm)

# xor

- https://wiremask.eu/tools/xor-cracker/

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

- http://blog.dornea.nu/2016/10/29/ringzer0-ctf-javascript-challenges/#207f46edd62ccf43b49d59d48df5c867

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

- [GitHub \- bozhu/BMA: Berlekamp\-Massey algorithm](https://github.com/bozhu/BMA)

# find polynomials

- Lagrange Interpolation in finite field (i.e. Galois field)
    - [CTFtime\.org / ångstromCTF 2021 / Substitution / Writeup](https://ctftime.org/writeup/27032)
    ```python
    F = GF(691)
    points = [(0, 125), (1, 492), (2, 670), (3, 39), ... , (688, 130), (689, 487), (690, 18)]
    R = F['x']
    print(R.lagrange_polynomial(points))
    ```
- Transformation Matrix
    ```python
    from sage.all import *

    vals = vector(mod(enc(i), MOD) for i in range(FLAG_LEN))
    coeffs = Matrix(
        [
            [mod(i ** (FLAG_LEN - j - 1), MOD) for j in range(FLAG_LEN)]
            for i in range(FLAG_LEN)
        ]
    )
    flag = coeffs.solve_right(points)
    ```

# one-time pad

- https://medium.com/hackstreetboys/securinets-ctf-quals-2019-useless-admin-crypto-4e2685452fec

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

# stream ciphers

- fixed nonce => similar to repeating xor key, but using same keystream bytes across ciphertexts
    - https://book-of-gehn.github.io/articles/2018/12/04/Fixed-Nonce-CTR-Attack.html
    - https://cedricvanrompay.gitlab.io/cryptopals/challenges/19-and-20.html

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

- https://blog.cryptohack.org/cryptoctf2020
- https://n00bcak.github.io/writeups/2021/04/08/AngstromCTF-2021.html
- https://github.com/TFNS/writeups/tree/master/2020-04-25-IJCTF
- https://github.com/TFNS/writeups/tree/master/2020-04-12-ByteBanditsCTF
- https://github.com/TFNS/writeups/tree/master/2020-03-07-zer0ptsCTF/ror
- https://github.com/TFNS/writeups/tree/master/2020-03-01-AeroCTF/magic
- https://github.com/pcw109550/write-up

- https://blog.quarkslab.com/differential-fault-analysis-on-white-box-aes-implementations.html
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


