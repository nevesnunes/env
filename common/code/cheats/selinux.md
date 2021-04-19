# +

```bash
# run
runcon -r system_r -t APP_t COMMAND

# relabel
touch /.autorelabel

# status
getenforce
sestatus

# type usage
sudo semanage fcontext -l | grep -i openvpn
```

# docker

```bash
docker run -v /var/db:/var/db:z rhel7 /bin/sh
# ||
chcon -Rt svirt_sandbox_file_t /var/db
```

- https://www.projectatomic.io/blog/2015/06/using-volumes-with-docker-can-cause-problems-with-selinux/

# sandbox

- [Walsh: Cool things with SELinux\.\.\. Introducing sandbox \-X \(LWN\.net\)](https://lwn.net/Articles/353203/)

# roles

- [Understanding SELinux Roles \- Dan Walsh&\#39;s Blog — LiveJournal](https://danwalsh.livejournal.com/75683.html)

# policies

- https://selinuxproject.org/page/AVCRules
- https://selinuxproject.org/page/PolicyStatements
