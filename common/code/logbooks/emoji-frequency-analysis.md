# emoji-frequency-analysis

- [ ] Replace tokens of a given source code file (e.g. c) with emoji
- [ ] Reverse process using frequency analysis

Generating:

- https://stackoverflow.com/questions/43797500/python-replace-unicode-emojis-with-ascii-characters

Resources:

- https://emojipedia.org/warning/
   - `python -c "print(u'' + '\u26A0\uFE0F')"` 
- https://github.com/github/linguist
    - [support PL/SQL PLpgSQL and SQLPL](https://github.com/github/linguist/pull/2175/files)
        - ? check pull requests for other languages
    - https://github.com/github/linguist/tree/master/samples
    - https://github.com/github/linguist/blob/master/lib/linguist/samples.rb
    - https://github.com/github/linguist/blob/master/lib/linguist/heuristics.rb
- https://www.dcode.fr/frequency-analysis
- https://github.com/lydell/text-frequencies-analysis
- http://www.cs.ucf.edu/courses/cis3362/fall2017/hmk/CIS3362-Fall17-Hmk3-Sol.pdf
    - cryptool
    - The Vigenere cipher was designed to disrupt frequency analysis; however, using either the Kasiski test or index of coincidence analysis will help you overcome this obstacle.
- http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-simple-substitution-cipher/
