https://github.com/khavishbhundoo/obfsproxy-openvpn
https://www.softether.org/
https://www.getlantern.org/en_US/
ShadowVPN, Shadowsocks, gohop

letsencrypt

ssh -D/-w0 (for a TUN device)
PPTP, IPsec, mpls
stunnel

ssh -L opens a local port. Everything that you send to that port is put through the ssh connection and leaves through the server. If you do, e.g., ssh -L 4444:google.com:80, if you open http://localhost:4444 on your browser, you'll actually see google's page.

ssh -D opens a local port, but it doesn't have a specific endpoint like with -L. Instead, it pretends to be a SOCKS proxy. If you open, e.g., ssh -D 7777, when you tell your browser to use localhost:7777 as your SOCKS proxy, everything your browser requests goes through the ssh tunnel. To the public internet, it's as if you were browsing from your ssh server instead of from your computer.
