# +

google: mdn foo

https://www.webpagetest.org/

https://github.com/clowwindy/Awesome-Networking
http://www.kegel.com/c10k.html

https://developer.mozilla.org/en-US/docs/Web/CSS/Specificity

bypass URL access rules is to abuse redirections (responses with code 3xx)
    Open URL Redirection
        repeat parameter: 2nd url redirects to 3rd url

https://serverfault.com/questions/189784/java-fat-client-slow-when-connecting-to-localhost-fast-with-remote
https://hc.apache.org/httpclient-3.x/performance.html

Ping-scan to discover reachable prefixes.
Traceroute to discover topology.
ZMap on reachable prefixes for common service ports.
DNS AXFR to learn host names.
wget crawling of seeded HTTP servers for content.

https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Technical_overview

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

```/etc/hosts
127.0.0.1 domain.com
php -S 127.0.0.1:80
```

# Profiling

handler = {
   apply: function(target, thisArg, argumentsList) {
   }
}
window.open = new Proxy(window.open, handler);
Element.prototype.appendChild = new Proxy(Element.prototype.appendChild, handler);

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

HTTP POST - Creates a resource
HTTP GET - Reads data for a resource
HTTP PUT - Update a resource's data
HTTP DELETE - Deletes a resource

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
