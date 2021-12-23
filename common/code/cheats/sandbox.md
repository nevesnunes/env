# sandboxing

- FireJail
    - [Simple application sandboxing using AppArmor and Firejail](https://pvera.net/posts/apparmor-firejail-sandboxing/)
    - :( [how to blacklist everything? · Issue \#354 · netblue30/firejail · GitHub](https://github.com/netblue30/firejail/issues/354)

# MAC

- [AppArmor](./apparmor.md)
- [SELinux](./selinux.md)

# namespaces

- `sudo unshare -n -- sudo -u sandboxuser bash -c 'foo'`
    - https://unix.stackexchange.com/questions/68956/block-network-access-of-a-process

# network

- https://security.stackexchange.com/questions/5969/network-policies-under-apparmor-selinux
    - https://serverfault.com/questions/366922/selinux-limit-httpd-outbound-connections-by-address-and-port

# X11

- `xhost +SI:localuser:sandboxuser`
- [NoteHub &mdash; Sandboxing X11 for dummies](http://web.archive.org/web/20180320135605if_/https://notehub.org/rp5n2)
    ```bash
    xauth -f "$cookie" generate "$DISPLAY" MIT-MAGIC-COOKIE-1 untrusted
    export XAUTHORITY="$cookie"
    ```
- [Short setups to provide X display to container · mviereck/x11docker Wiki · GitHub](https://github.com/mviereck/x11docker/wiki/Short-setups-to-provide-X-display-to-container)
- [X11 Guide \| Firejail](https://firejail.wordpress.com/documentation-2/x11-guide/)
