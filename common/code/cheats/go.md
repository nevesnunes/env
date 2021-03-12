# Install / Update module

```bash
# Local install:
# go mod init tmp
go get -u $hostname/$module_path
# ||
GO111MODULE=on go get -u $hostname/$module_path
```

# Cross-platform builds

- [GitHub \- mitchellh/gox: A dead simple, no frills Go cross compile tool](https://github.com/mitchellh/gox)
- [GitHub \- jpillora/cloud\-gox: A Go \(golang\) Cross\-Compiler in the cloud](https://github.com/jpillora/cloud-gox)

```bash
GOOS=darwin GOARCH=386 go build -v
```

# Modules

- https://blog.golang.org/using-go-modules

# Language Server

```bash
GO111MODULE=on go get golang.org/x/tools/gopls@latest
```
