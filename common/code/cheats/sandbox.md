# namespaces

- `sudo unshare -n -- sudo -u sandboxuser bash -c 'foo'`
    - https://unix.stackexchange.com/questions/68956/block-network-access-of-a-process

# X11

- `xhost +SI:localuser:sandboxuser`
- [NoteHub &mdash; Sandboxing X11 for dummies](http://web.archive.org/web/20180320135605if_/https://notehub.org/rp5n2)
    ```bash
    xauth -f "$cookie" generate "$DISPLAY" MIT-MAGIC-COOKIE-1 untrusted
    export XAUTHORITY="$cookie"
    ```
- [Short setups to provide X display to container · mviereck/x11docker Wiki · GitHub](https://github.com/mviereck/x11docker/wiki/Short-setups-to-provide-X-display-to-container)
- [X11 Guide \| Firejail](https://firejail.wordpress.com/documentation-2/x11-guide/)

# MAC

- [selinux](./selinux.md)

- https://gitlab.com/apparmor/apparmor/-/wikis/AppArmorWine
    - https://github.com/mk-fg/apparmor-profiles/blob/master/profiles/usr.bin.wine
- https://ubuntu.com/tutorials/beginning-apparmor-profile-development#3-generating-a-basic-profile
