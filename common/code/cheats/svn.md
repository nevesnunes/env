# Debug requests

```
--config-option servers:global:neon-debug-mask=511
```

# Operations on inconsistent tracked file

```bash
# When switching clients
svn cleanup

svn rm --keep-local file
svn add file

# `--no-auth-cache`: In case of hang or other issues with authentication realm
svn commit -m 'message' --user user --password pass --no-auth-cache
```

# Operations on renamed file

http://www.dscentral.in/2013/04/04/502-bad-gateway-svn-copy-reverse-proxy/
    https://en.wikipedia.org/wiki/WebDAV

```
# Treat renamed file as new file
svn rm old_named_file
svn rm --keep-local renamed_file
svn add renamed_file
```

# Operations on deleted file

svn blame http://nexus.foo.com/fooRepository/trunk/foo/src/main/java/com/abc/foo/impl/BarImpl.java@80
url='http://nexus.foo.com/fooRepository/trunk/foo/src/main/java/com/abc/foo/impl/BarImpl.java' && svn diff "$url@25" "$url@26"

# Find corrupted directories

for fic in $(find . -type d | grep -v -e './target' -e '/.svn'); do svn up -N "$fic"; done

# Latest revision
```
svn update | sed -n 2p | grep -oE '[0-9]*'
svn update 1>/dev/null && svn log | sed -n 2p | grep -oE '[0-9]*' | head -n1
```

# List conflicts
```
svn status | grep -E '\s*[A-Z]\s+C\s+' -A 1
```

# Recursive resolve conflicts
```
while read -r i; do svn resolve --accept=working "$i"; done <<< "$(svn status | grep -E '\s*[A-Z]\s+C\s+' | sed 's/^\s*[ A-Z]\s*C\s*//')"
while read -r i; do svn add "$(cygpath -u "$i")"; done <<< "$(svn status | grep -E '\s*D\s+' | sed 's/^\s*D\s*//')"
```

# File out of date
svn add $PARENT_DIR
svn commit
svn cleanup
svn update
svn delete $PARENT_DIR
svn commit

# Properties
svn propget -R svn:ignore .
svn propdel svn:ignore $DIR
svn propedit svn:ignore $DIR
svn propset svn:ignore "tags
target
" .

# Merge
http://svnbook.red-bean.com/en/1.6/svn.ref.svn.c.resolve.html

```
svn update --force /path/to/dir/or/file
svn export --username "%%%" "http://%%%" .

svn resolve --accept theirs-full FOO
svn resolve --accept=working FOO
svn cleanup
svn update --force FOO 
svn status | grep -E '^.[ \t]*C' | awk '{print $3}' | xargs -d'\n' -I{} svn resolve --accept=working {}

svn list -R https://_ | grep -i _
```

# override local changes
```
svn checkout --force svn://repo website.dir
svn revert -R website.dir
```

# revert file to older revision
target=FILE && svn cat -r REV "$target" > "$target"

# git commit -va equivalent
svn diff -r HEAD
svn diff -r HEAD file

# search
svn log -v -r 0:HEAD | vim -

git svn clone $url
git log -G $regex
