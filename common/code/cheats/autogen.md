# autogen

```bash
# Build options
autoreconf -fi
# ||
~/code/snippets/recipes/autogen.sh

# List all dependencies
gawk 'match($0, /PKG_CHECK_MODULES.*\[([^[:space:]]*).*\]/, m){print m[1]}' configure.ac
```
