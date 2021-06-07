# Testing

- Onboarding app domain: http://mitm.it
- Import `mitmproxy-ca-cert.pem` in proxied app

```bash
mitmdump
google-chrome --proxy-server="http://127.0.0.1:8080"
```

# Web interface

```bash
mitmweb --listen-port 8081
```

- Filter URL: `~u foo.com`

# Transparent proxy

```bash
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8081
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8081

mitmproxy --mode transparent

# Rollback
iptables -t nat -F
sysctl -w net.ipv4.ip_forward=0
```

- https://docs.mitmproxy.org/stable/howto-transparent/
- https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/intercepting-ssl-and-https-traffic-with-mitmproxy-and-sslsplit/
- https://www.darkcoding.net/software/decrypt-your-https-traffic-with-mitmproxy/
    - Enumerate ciphers with `ssldump`
- [My phone is spying on me, so I decided to spy on it \| Hacker News](https://news.ycombinator.com/item?id=18298548)
    - [GitHub \- abcnews/data\-life](https://github.com/abcnews/data-life)
- Alternatives: Hotspot + dumpcap, VPN server
    - https://kushaldas.in/posts/tracking-my-phone-s-silent-connections.html

# Edit request manually

mitmproxy v4 has key binding `v` ("View flow body in an external viewer")

```bash
export EDITOR=vi
export PAGER=vi
```

# URL redirect, rewrite

Option 1:

```python
import mitmproxy
from mitmproxy import http
def request(flow: http.HTTPFlow) -> None:
    if flow.request.url == 'https://foo.com/js/foo.js':
        flow.request.url = '/home/foo/repo/js/foo.js'
```

Option 2:

```python
import mitmproxy
from mitmproxy.models import HTTPResponse
from netlib.http import Headers
def request(flow):
    if flow.request.pretty_host.endswith('mydomain.com'):
        mitmproxy.ctx.log( flow.request.path )
        method = flow.request.path.split('/')[3].split('?')[0]
        flow.request.host = 'newsite.mydomain.com'
        flow.request.port = 8181
        flow.request.scheme = 'http'
    if method == 'getjson':
        flow.request.path = flow.request.path.replace(method,'getxml')
        flow.request.headers['Host'] = 'newsite.mydomain.com'
```

---

[Modifying request\.url impacted request\.host · Issue \#890 · mitmproxy/mitmproxy · GitHub](https://github.com/mitmproxy/mitmproxy/issues/890)
    `flow.request.data.host`

# SSL

- Certificate file: `~/.mitmproxy/mitmproxy-ca-cert.cer`
- Keylog file: Browser specific

https://docs.mitmproxy.org/stable/howto-wireshark-tls/

# Alternatives

- [Fiddler](https://www.telerik.com/support/fiddler)
    - https://stackoverflow.com/questions/16021760/intercepting-javascript-files-from-a-secured-server-and-use-local-file-instead
        Tools > Fiddler Options > HTTPS > Check: Decrypt HTTPS Traffic
    - https://stackoverflow.com/questions/3936490/how-to-replace-javascript-of-production-website-with-local-javascript
        AutoResponder > Check: Enable automatic responses
- [SSLsplit](https://www.roe.ch/SSLsplit)


