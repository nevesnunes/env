# osi

- presentation layer (6): tcp
- session layer (5)
    - active FTP: port 20, 21
    - passive FTP: port 21
- transport layer (4): tcp

# lifecycle

```
wget ftp://user:password@ftp.mydomain.com/foo/bar

ftp x.x.x.x
||
ftp -nv x.x.x.x
> user
Name: anonymous
||
ftp -p x.x.x.x 8888

cd incoming
dir
get foo
put /home/foo/bar
help
quit
```

- https://xmehulx.github.io/terminal/wireshark-basic-tutorial-using-ftp-session

# kernel support

```bash
grep FTP /boot/config-5.6.12-300.fc32.x86_64

# Output:
# CONFIG_NF_CONNTRACK_FTP=m
# CONFIG_NF_CONNTRACK_TFTP=m
# CONFIG_NF_NAT_FTP=m
# CONFIG_NF_NAT_TFTP=m
# CONFIG_IP_VS_FTP=m
```

# issues

### no connection

- try external app (e.g. filezilla)
- check firewall ports on client-side
- [FTPClient \(Apache Commons Net 3\.8\.0 API\)](https://commons.apache.org/proper/commons-net/apidocs/org/apache/commons/net/ftp/FTPClient.html)
    - compare `enterRemotePassiveMode()` vs. `enterLocalPassiveMode()`

### ftp.exe does not support passive mode

```
dir
put /usr/share/empty/bbb bbb
```

```strace
[pid 1188431] connect(4, {sa_family=AF_INET, sin_port=htons(24653), sin_addr=inet_addr("192.168.1.3")}, 16) = -1 EACCES (Permission denied)

[pid 1190688] openat(AT_FDCWD, "bbb", O_WRONLY|O_CREAT|O_EXCL|O_APPEND, 0666) = -1 EACCES (Permission denied)
```

```bash
ps aux | grep 1188431
# => user: ftp
```

# chroot location

```strace
[pid 1174219] chdir("pub") = 0

[pid 1191143] chdir("/usr/share/empty") = 0
[pid 1191143] chroot(".") = 0
```

```bash
ls -la /proc/1174219/cwd

# Output:
# lrwxrwxrwx. 1 root root 0 May 23 14:03 /proc/1174219/cwd -> /var/ftp/pub
```

# server configuration

dnf -y install vsftpd

/etc/vsftpd/vsftpd.conf

```
allow_writeable_chroot=YES
anon_upload_enable=YES
anonymous_enable=YES
listen_address=0.0.0.0
listen=YES
no_anon_password=YES
pasv_enable=YES
pasv_max_port=40001
pasv_min_port=40000
write_enable=YES
xferlog_enable=NO
```

```bash
mkdir -p /var/ftp/pub/incoming
# need executable permissions for client to change directory
chmod a+rwx /var/ftp/pub/incoming
firewall-cmd --add-service=ftp
firewall-cmd --add-port=40000-40001/tcp
setsebool -P ftpd_use_passive_mode on
systemctl start vsftpd

# Validation

curl -T /tmp/foo ftp://192.168.1.4/tmp/bar --user foo

sudo su -s /bin/bash -c 'touch /var/ftp/pub/incoming/foo' ftp

sudo su -s /bin/bash -c 'strace nc -z 192.168.1.3 25075 2>&1 | grep connect' ftp

# Output:
# connect(5, {sa_family=AF_INET, sin_port=htons(25075), sin_addr=inet_addr("192.168.1.3")}, 16) = -1 EINPROGRESS (Operation now in progress)
# Followed by: select() or poll()
# Reference: man connect
```

- https://fedoramagazine.org/how-to-setup-an-anonymous-ftp-download-server/
- https://www.getpagespeed.com/server-setup/firewalld-ftp-rule-allow-access-ftp-service-centos-7
- https://serverfault.com/questions/38398/allowing-ftp-with-iptables
- https://stackoverflow.com/questions/19516263/200-port-command-successful-consider-using-pasv-425-failed-to-establish-connec

# specification

- http://slacksite.com/other/ftp.html

# maximum connections

- max in total vs. max per ip / user
    - https://help.directadmin.com/item.php?id=491
    - http://www.proftpd.org/docs/directives/linked/config_ref_MaxClientsPerUser.html

# ambiguous error codes

- 550
    - https://kb.globalscape.com/KnowledgebaseArticle10305.aspx?Keywords=mix+error


