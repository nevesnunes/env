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
- https://stackoverflow.com/questions/9555403/capturing-mobile-phone-traffic-on-wireshark
- [My phone is spying on me, so I decided to spy on it \| Hacker News](https://news.ycombinator.com/item?id=18298548)
    - [GitHub \- abcnews/data\-life](https://github.com/abcnews/data-life)
- Alternative: Set OS proxy to Burp Suite, Add root certificate to OS keystore
    - [Wacom drawing tablets track the name of every application that you open \| Robert Heaton](https://robertheaton.com/2020/02/05/wacom-drawing-tablets-track-name-of-every-application-you-open/)
- Alternative: Hotspot + dumpcap
    - https://kushaldas.in/posts/tracking-my-phone-s-silent-connections.html
- Alternative: VPN server
    - https://openvpn.net/community-resources/how-to/#redirect
    - ~/code/src/net/ovpn-unified-format-example
        - e.g. mail .opvn file to phone
- Alternative: macOS Remote Virtual Interface (RVI)
    - https://andydavies.me/blog/2019/12/12/capturing-and-decrypting-https-traffic-from-ios-apps/

### VPN

```bash
sysctl -w net.ipv4.ip_forward=1

ip tuntap add name tun0 mode tun
openvpn --genkey --secret static.key
openvpn --dev tun0 --ifconfig 10.0.0.1 10.0.0.2 --secret static.key
iptables -t nat -A POSTROUTING -o eth0 -s 10.0.0.0/24 -j MASQUERADE

iptables -t nat -A PREROUTING -i tun0 -p tcp --dport 80 -j REDIRECT --to-port 8081
iptables -t nat -A PREROUTING -i tun0 -p tcp --dport 443 -j REDIRECT --to-port 8081

mitmproxy --mode transparent --showhost
```

# Edit request manually

mitmproxy v4 has key binding `v` ("View flow body in an external viewer")

```bash
export EDITOR=vi
export PAGER=vi
```

# Map resources

```sh
mitmproxy \
    --mode reverse:https://foo/ \
    -p 1234 \
    --map-local '|https://foo/js/app.js|local_app.js' \
    -H '|Origin|https://foo/' \
    -H '|Referer|https://foo'
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


