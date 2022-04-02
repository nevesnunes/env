# +

- [The Go Playground](https://play.golang.org/)

# Install / Update module

```bash
# Local install:
# go mod init tmp
go install $hostname/$module_path
# version <= 1.17
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

# Dissassembly

```bash
# With compiler flag
go tool compile '-d=unified=1' -p . -S <(printf '%s' 'package main
func main() {
    print(0xff)
}
')
```

- [GitHub \- felberj/gotools: Plugin for Ghidra to assist reversing Golang binaries](https://github.com/felberj/gotools)
- [GitHub \- sibears/IDAGolangHelper: Set of IDA Pro scripts for parsing GoLang types information stored in compiled binary](https://github.com/sibears/IDAGolangHelper)

- [Reverse Engineering Go, Part II &\#8211; OSIRIS Lab at NYU Tandon](https://blog.osiris.cyber.nyu.edu/2019/12/19/ugo-ghidra-plugin/)
- [Reverse Engineering Go Binaries with Ghidra \- CUJO AI](https://cujo.com/reverse-engineering-go-binaries-with-ghidra/)
    - https://github.com/getCUJO/ThreatIntel/tree/master/Research_materials/Golang_reversing
    - https://github.com/getCUJO/ThreatIntel/tree/master/Scripts/Ghidra
- [Reversing GO binaries like a pro \| RedNaga Security](https://rednaga.io/2016/09/21/reversing_go_binaries_like_a_pro/)
