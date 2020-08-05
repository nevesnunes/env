```bash
# https://github.com/allyshka/dirbustlist/tree/master/dirbuster
grep -v '%' ~/opt/dirbustlist/dirbuster/directory-list-2.3-medium.txt > /tmp/wordlist
gobuster dir --url http://vulnerable --wordlist /tmp/wordlist

# https://github.com/zaproxy/zap-extensions/tree/master/addOns/directorylistv2_3/src/main/zapHomeFiles/fuzzers/dirbuster
gobuster dir --url http://vulnerable --wordlist ~/opt/zap-extensions/tree/master/addOns/directorylistv2_3/src/main/zapHomeFiles/fuzzers/dirbuster/directory-list-2.3-medium.txt
```
