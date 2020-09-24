# pipe-hang

file-less alternative for https://unix.stackexchange.com/questions/543541/is-there-a-standard-alternative-to-sponge-to-pipe-a-file-into-itself

```bash
# output <64k passes
dd if=/dev/urandom count=1 bs=48500 | base64 > 1
# output >64k hangs
dd if=/dev/urandom count=1 bs=48600 | base64 > 1

{ sed 's/1/2/' 1; echo | nc localhost 8080 } | { nc -l 8080; tee 1 }
```

- [ ] verify hang is from saturated buffered output
    - https://stackoverflow.com/questions/4624071/pipe-buffer-size-is-4k-or-64k
