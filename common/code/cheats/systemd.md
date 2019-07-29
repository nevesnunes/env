# restarting systemd service on dependency failure

Replace `Requires=` with `Wants=` and `After=` with `ExecStartPre=systemctl is-active <dependency>`
https://github.com/systemd/systemd/issues/1312#issuecomment-228874771
