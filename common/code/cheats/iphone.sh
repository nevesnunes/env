cd /run/user/1000/gvfs/afc:host=604ce5b1932c31c3ef5d7a033f6d5e75bf1ad12c/Books/Purchases
for i in *.epub; do (cd "$i" && zip -vur "$HOME/Documents/$i" mimetype *); done

# Add ebook
# Books/Purchases/purchases.plist
# <dict>

# Bookmarks

# Circa 2012
/usr/bin/plutil -convert xml1 -o - ~/Library/Safari/Bookmarks.plist | grep -E -o '<string>http[s]{0,1}://.*</string>' | grep -v icloud | sed -E 's/<\/{0,1}string>//g'

# iOS 10
echo "
select url,title
from bookmarks
where url not like '' and extra_attributes not like '';
" | \
sqlite ~/Documents/my/iphone-unback/Library/Safari/Bookmarks.db | \
awk -f ~/code/snippets/netscape-bookmark-file.awk
