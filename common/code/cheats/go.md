# Install / Update module

```bash
# Local install:
# go mod init tmp
go get -u $hostname/$module_path
# ||
GO111MODULE=on go get -u $hostname/$module_path
```

# Cross-platform builds

https://github.com/mitchellh/gox
https://github.com/jpillora/cloud-gox

```bash
GOOS=darwin GOARCH=386 go build
```

# Modules

https://blog.golang.org/using-go-modules

# Language Server

```bash
GO111MODULE=on go get golang.org/x/tools/gopls@latest
```
