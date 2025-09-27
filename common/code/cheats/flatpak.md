# install

```sh
sudo apt install flatpak
sudo flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
sudo flatpak install runtime/org.kde.Platform/x86_64/5.15
sudo flatpak install foo.flatpak
```

# run

```sh
flatpak list
sudo -i flatpak run foo
# ||
sudo -E flatpak enter net.mancubus.SLADE sh
```
