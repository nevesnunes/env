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
- git
    - https://tor.stackexchange.com/questions/4855/is-it-possible-to-have-a-hidden-git-service

# relays

- `torsocks aria2c --async-dns=false https://foo.onion`
    - [GitHub \- dgoulet/torsocks: Library to torify application \- NOTE: upstream has been moved to https://gitweb\.torproject\.org/torsocks\.git](https://github.com/dgoulet/torsocks)
- `proxychains -f ./foo.conf curl -v https://foo.onion`
    - ./foo.conf: `socks5 127.0.0.1 9050`
    - [GitHub \- haad/proxychains: proxychains \- a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4, SOCKS5 or HTTP\(S\) proxy\.  Supported auth\-types: &quot;user/pass&quot; for SOCKS4/5, &quot;basic&quot; for HTTP\.](https://github.com/haad/proxychains)
