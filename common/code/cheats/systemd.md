# limits

```sh
systemd-run --user -S -p 'MemoryMax=8G'
```

# overrides

```sh
mkdir -p /etc/systemd/system/foo.service.d/
cat << EOF > /etc/systemd/system/foo.service.d/override.conf
[Service]
ExecStart=
ExecStart=/foo --bar
EOF
systemctl daemon-reload
systemctl restart foo
```

# debug

```sh
systemd-analyze verify foo
```

# restarting systemd service on dependency failure

- Replace `Requires=` with `Wants=` and `After=` with `ExecStartPre=systemctl is-active <dependency>`
    - https://github.com/systemd/systemd/issues/1312#issuecomment-228874771

# mount

- https://utcc.utoronto.ca/~cks/space/blog/linux/SystemdBindMountUnits
