# Git sync changes from upstream
git fetch upstream; git merge upstream/master

# Git add remote
git remote add upstream %%%; git remove -v

# Git find commit to blame a deleted string (log)
git log -S %%%STRING %%%FILE

# Git squash commits (rebase)
git rebase -i HEAD~%%%3

# Git remove submodule files from staging (rm)
git rm --cached %%%SUBMODULE_PATH

# Git undo commit amend (reset; commit)
git reset --soft HEAD@{1}; git commit -C HEAD@{1}

# Git list all remote repository urls
git-for-all.sh config --get remote.origin.url | \
    xargs -d'\n' -I{} -n1 -r echo "git clone" {} | \
    sort

# Git Lines of code per author
git ls-tree -r -z --name-only HEAD -- */*.c \
    | xargs -0 -n1 git blame --line-porcelain HEAD \
    | grep  "^author " | sort | uniq -c | sort -nr

# File type (xdg-mime)
xdg-mime query filetype %%%

# Find recursively, ignoring case (find)
find . -iname "*%%%*"

# Grep recursively, ignoring case and binaries (grep)
grep -riIHn "%%%"

# Change keymap (xkbcomp)
xkbcomp -I$HOME/.xkb ~/.xkb/keymap/%%% $DISPLAY

# Git resolve conflict/merge
git checkout --ours -- %%%

# Video output for multi-monitor presentation (xrandr)
xrandr --output VGA1 --mode 1024x768 --right-of LVDS1

# Rename all files to lowercase (prename)
find . -depth -exec prename "s/(.*)\/([^\/]*)/$1\/\L$2/" {} \;

# Copy file to backup
cp %%%{,.backup}

# Execute command in all name matched processes
ps aux | grep %%%STR | grep -v grep | awk "{print $2}" | xargs %%%CMD

# X all window information from root window
xwininfo -root -all

# VirtualBox - Install extension pack (VBoxManage)
sudo VBoxManage extpack install %%%

# Patch diff ala git
diff -Naurw %%%OLD %%%NEW > %%%.diff

# Run command file fuzzy sorted list by latest modified time/date (find; fzf)
find "%%%" -maxdepth 2 -type f | \
    xargs -d'\n' -I{} -n1 -r stat --format "%Y %n" {} | sort -nr | cut -d" " -f2- | \
    fzf | \
    xargs -d'\n' -I{} -n1 -r xdg-open {}

# Run command with most recent file in directory (ls)
ls -t | head -n1 | xargs -d'\n' -I{} -n1 -r %%% {}

# Check content type of site/webpage (curl)
curl -s -I -X GET %%% | grep Content-Type

# Find files not matching permissions
find -type d -not -perm 775

# Reflow pdf file for small screen reading (k2pdfopt)
k2pdfopt %%% -dev kpw -mode fw -wrap -hy -ws 0.375 -ls-

# Record shell session
test "$(ps -ocommand= -p $PPID | awk '{print $1}')" == 'script' || (script -f $HOME/$(date +"%d-%b-%y_%H-%M-%S")_shell.log)

# List Firefox bookmarks
sqlite3 ~/.mozilla/firefox/*.Default\ User/places.sqlite "SELECT strftime('%d.%m.%Y %H:%M:%S', dateAdded/1000000, 'unixepoch', 'localtime'),url FROM moz_places, moz_bookmarks WHERE moz_places.id = moz_bookmarks.fk ORDER BY dateAdded;"

# Rename filenames with colons
find . -name "*:*" -exec rename 's|:|_|g' {} \;

# check security certificate of website (curl)
verify-certificate %%%

# Change the primary group for a user
usermod -g %%%NEW_GROUP %%%USER

# Add a user to a group
usermod -a -G %%%NEW_GROUP %%%USER

# Remove a user from a group
usermod -G %%%COMMA_SEPARATED_GROUPS %%%USER

# Parent process name (bash)
ps -o comm= %%%PPID

# Change the Priority of a Running Process
renice -n -%%%NICE -p %%%PID

# Check details/info/version of remote server
curl -X OPTIONS http://%%% --user %%% -v

# Download source rpm
yumdownloader --source %%%

# Extract source rpm
rpm2cpio %%% | cpio -idmv

# List IP range of addresses
nmap -sP 192.168.%%%.0/24

# List IP range of addresses by PTR records of DNS
nmap -vvv -sn -sL 192.168.%%%.0/24

# List IP range of addresses by ARP scan
nmap -vvv -sn -PR 192.168.%%%.0/24

# List IP range of addresses by SYN scan
nmap -vvv -sn -PS 192.168.%%%.0/24

# List IP range of addresses by ACK scan
nmap -vvv -sn -PA 192.168.%%%.0/24

# Reload driver
modprobe -r %%% && echo mem > /sys/power/state & modprobe %%%

# Convert demo to video recording
prboom-plus -timedemo %%% -viddump out.mkv

# Git remove old history
git rev-parse HEAD~%%% > .git/info/grafts
git filter-branch -- --all

# Git reduce/clean repository size
git reflog expire --all --expire=now
git gc --prune=now --aggressive

# Normalize/replace single quote
sed -i "s/\xe2\x80\x99/'/g" %%%

# Resume/continue/finish download
wget --continue %%%

# Convert YAML to JSON
python -c 'import sys, yaml, json; y=yaml.load(sys.stdin.read()); print json.dumps(y)' < %%%YAML

# Git new branch
git checkout -b %%%
git push --set-upstream origin %%%

# Override OpenGL version
MESA_GL_VERSION_OVERRIDE=4.2 MESA_GLSL_VERSION_OVERRIDE=420 ./%%%
