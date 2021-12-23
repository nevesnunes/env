# +

```conf
profile nonetwork /path/to/exec {
  capability,
  network,
  mount,
  remount,
  umount,
  pivot_root,
  ptrace,
  signal,
  dbus,
  unix,
  file,
  deny network,
  deny capability net_admin,
  deny capability net_bind_service,
  deny capability net_broadcast,
  deny capability net_raw,
}
```

- https://gitlab.com/apparmor/apparmor/-/wikis/AppArmorWine
    - https://github.com/mk-fg/apparmor-profiles/blob/master/profiles/usr.bin.wine
- https://ubuntu.com/tutorials/beginning-apparmor-profile-development#3-generating-a-basic-profile
