# +

https://github.com/ipfs/ipfs#project-links
https://docs.ipfs.io/guides/examples/
http://127.0.0.1:8080/ipns/awesome.ipfs.io

https://discuss.ipfs.io/t/privacy-and-anonymity-in-ipfs-ipns/1068/3
    [...] you can misconfigure your tor daemon and become and exit node for the entire ipfs population
https://discuss.ipfs.io/t/does-ipfs-provide-any-guarantees-about-anonymity/387
https://news.ycombinator.com/item?id=12719771
    In fact, IPFS via the DHT, tells the network of your whole network topology, including internal address you may have, and VPN endpoints too.
    [...] if you were to use a Tor connection with IPFS, it will tell the whole network your public, private, and .onion addresses.
[Tor onion integration · Issue \#37 · ipfs/notes · GitHub](https://github.com/ipfs/notes/issues/37)
[node\-Tor is now open source in clear and modular · Issue \#439 · ipfs/ipfs · GitHub](https://github.com/ipfs/ipfs/issues/439)

[Writeup of router kill issue · Issue \#3320 · ipfs/go\-ipfs · GitHub](https://github.com/ipfs/go-ipfs/issues/3320)
[internalWebError: operation not supported · Issue \#6203 · ipfs/go\-ipfs · GitHub](https://github.com/ipfs/go-ipfs/issues/6203)

# Setup

```bash
install_dir=~/opt
(
mkdir -p "$install_dir"
cd "$install_dir"
"$install_dir"/ipfs-update/ipfs-update fetch
)
bin=$(find "$install_dir" \
        -maxdepth 1 \
        -type f \
        -name 'ipfs-v*' | \
    tail -1)
ln -fs "$bin" "$install_dir/ipfs"
```

https://docs.ipfs.io/introduction/usage/

# Running

```bash
ipfs init

ipfs cat /ipfs/QmS4ustL54uo8FzR9455qaxZwuMiUhyvMcX9Ba8nUH4uVv/readme

ipfs daemon

ipfs resolve -r /ipns/12D3KooWB3GY1u6zMLqnf3MJ8zhX3SS1oBj7VXk3xp6sJJiFGZXp
# => /ipfs/QmQmJXo5cgyMvKDeXkUJTTzr8KFZk1Kg3amWMc9EhKbHnm
ipfs ls -v /ipns/12D3KooWB3GY1u6zMLqnf3MJ8zhX3SS1oBj7VXk3xp6sJJiFGZXp/
ipfs cat /ipns/12D3KooWB3GY1u6zMLqnf3MJ8zhX3SS1oBj7VXk3xp6sJJiFGZXp/index.html
ipfs cat /ipns/torrent-paradise.ml/index.html
```

# Hosting

```bash
ipfs add -r ~/code/ipfs/hello
# => added QmbByGfU478oztLuL57FceepYxECmoX8stNJP1RSNta3nP hello

# [!] This URI starts with something that looks like a broken CIDv0 (case-sensitive "Qm…"). Some browser vendors force lowecase in URIs before IPFS Companion is able to fix it.
# Workaround: convert the original CIDv0 to case-insensitive CIDv1 and try again.
# References: https://docs.ipfs.io/guides/guides/addressing
ipfs cid base32 QmbByGfU478oztLuL57FceepYxECmoX8stNJP1RSNta3nP
# => bafybeif652ykyq3msqi7yrjv23pdir7vkpxvs4ptwltliepe6ibswmwuja
xdg-open 'http://127.0.0.1:8080/ipfs/bafybeif652ykyq3msqi7yrjv23pdir7vkpxvs4ptwltliepe6ibswmwuja/'
```

http://127.0.0.1:5001/webui > Status > Addresses

http://127.0.0.1:8080/ipns/docs.ipfs.io/guides/examples/websites/


