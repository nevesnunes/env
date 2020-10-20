# +

- configuration
    - ./Data/Tor/torrc
- default/home page
    - https://check.torproject.org/
- onion address format
    - base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
    - 56 + 6 bytes
    - https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt
    - methodology
        - https://www.google.com/search?q=base32+%2256+bytes%22
        - https://www.google.com/search?q=base32+%2256+characters%22

# relays

- browser proxy
    - SOCKS5 port 9050
- [GitHub \- dgoulet/torsocks: Library to torify application \- NOTE: upstream has been moved to https://gitweb\.torproject\.org/torsocks\.git](https://github.com/dgoulet/torsocks)
