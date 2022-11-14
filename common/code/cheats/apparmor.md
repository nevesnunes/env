# +

```sh
# Reload one profile
apparmor_parser -r /etc/apparmor.d/profile.name

# Disable one profile
ln -s /etc/apparmor.d/profile.name /etc/apparmor.d/disable/
apparmor_parser -R /etc/apparmor.d/profile.name

# Enable one profile
rm -f /etc/apparmor.d/disable/profile.name
apparmor_parser -r /etc/apparmor.d/profile.name
```

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
