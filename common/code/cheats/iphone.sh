# Access files

### On Nautilus, open: Documents on foo's iPhone
### Press: C-l
### Replace: afc://foo:bar > afc://foo

# Convert ebook

cd "/run/user/$(id -u)/gvfs/afc:host=604ce5b1932c31c3ef5d7a033f6d5e75bf1ad12c/Books/Purchases"
for i in *.epub; do (cd "$i" && zip -vur "$HOME/Documents/$i" mimetype ./*); done

# Add ebook
# Books/Purchases/purchases.plist
# <dict>

# Bookmarks

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

# Mount

### 1. Unplug your iPhone

### 2. Install

sudo apt-get install libimobiledevice-utils ifuse

### 3. Unlock, connect device and run

usbmuxd -v --user usbmuxd --systemd
dmesg | grep ipheth

idevicepair unpair && idevicepair pair
mkdir -p ~/media/iphone &>/dev/null
sudo -u "$(whoami)" ifuse ~/media/iphone -o rw

### 4. Unmount

fusermount -u ~/media/iphone/

# Debug

chmod 4755 /usr/bin/fusermount
ls -l /usr/bin/fusermount
# Input: lsusb
udevadm info --attribute-walk --name /dev/bus/usb/001/005

# Enumeration

idevice_id -l
ideviceinstaller -l

# Backup

~/bin/iphone-backup.sh

# ||
# Input: lsusb
dd if=/dev/bus/usb/001/003 of="$HOME"/foo.img


