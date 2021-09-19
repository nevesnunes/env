# Access files

- Nautilus > Open: Documents on foo's iPhone > Press: Ctrl-l > Replace: `afc://foo:bar > afc://foo`

# Convert ebook

```bash
cd "/run/user/$(id -u)/gvfs/afc:host=604ce5b1932c31c3ef5d7a033f6d5e75bf1ad12c/Books/Purchases"
for i in *.epub; do (cd "$i" && zip -vur "$HOME/Documents/$i" mimetype ./*); done
```

# Add ebook

- Books/Purchases/purchases.plist
    - `<dict>`

# Bookmarks

```bash
### iOS Circa 2012

/usr/bin/plutil -convert xml1 -o - ~/Library/Safari/Bookmarks.plist | \
  grep -E -o '<string>http[s]{0,1}://.*</string>' | \
  grep -v icloud | \
  sed -E 's/<\/{0,1}string>//g'

### iOS 10

echo "
select url,title
from bookmarks
where url not like '' and extra_attributes not like '';
" | \
  sqlite ~/Documents/my/iphone-unback/Library/Safari/Bookmarks.db | \
  awk -f ~/code/snippets/netscape-bookmark-file.awk
  ```

# Mount

```bash
# 1. Unplug your iPhone

# 2. Install
sudo apt-get install libimobiledevice-utils ifuse

# 3. Unlock, connect device and run
usbmuxd -v --user usbmuxd --systemd
dmesg | grep ipheth

idevicepair unpair && idevicepair pair
mkdir -p ~/media/iphone &>/dev/null
sudo -u "$(whoami)" ifuse ~/media/iphone -o rw

# 4. Unmount
fusermount -u ~/media/iphone/
```

# Enumeration

- Take $UDID/AdID/AIFA from Xcode > Window > Devices > Identifier

```bash
idevice_id -l
ideviceinstaller -l
```

# Backup

```bash
~/bin/iphone-backup.sh

# ||
# Input: lsusb
dd if=/dev/bus/usb/001/003 of="$HOME"/foo.img
```

# Debug

```bash
chmod 4755 /usr/bin/fusermount
ls -l /usr/bin/fusermount
# Input: lsusb
udevadm info --attribute-walk --name /dev/bus/usb/001/005
```

# Network tracing / Packet sniffing

- Wireless hotspot
- || HTTP proxy
- || VPN server
    - e.g. http://openvpn.net/index.php/access-server/overview.html
- || nc tunneling
    - e.g. [GitHub \- ADVTOOLS/ADVsock2pipe: A small utility to connect a TCP socket to a Windows named pipe\. It can be used, for exemple, to capture network data with tcpdump on Linux or iPhone/iPad and to see the capture in \(almost\) realtime in Wireshark on Windows\. Released under GPLv3\.](https://github.com/ADVTOOLS/ADVsock2pipe)
- || ARP poisoning
    - e.g. http://openmaniak.com/ettercap_arp.php
- https://stackoverflow.com/questions/9555403/capturing-mobile-phone-traffic-on-wireshark

```bash
# iOS >5: Remote Virtual Interface (RVI)

# bind
rvictl -s $UDID
# validation
ifconfig rvi0
# sniff
tcpdump -i rvi0 -n -vv
# unbind
rvictl -x $UDID
```
