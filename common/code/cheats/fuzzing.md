# Directory busting

```bash
grep -v '%' ~/opt/dirbustlist/dirbuster/directory-list-2.3-medium.txt > /tmp/wordlist
gobuster dir --url http://vulnerable --wordlist /tmp/wordlist
# ||
gobuster dir --url http://vulnerable --wordlist ~/opt/zap-extensions/tree/master/addOns/directorylistv2_3/src/main/zapHomeFiles/fuzzers/dirbuster/directory-list-2.3-medium.txt
# ||
gobuster dir --url http://vulnerable --wordlist SecLists/Discovery/Web_Content/raft-large-files.txt

# Specific file extensions
gobuster -x .php,.html
gobuster -x .js,.json
gobuster -x .aspx

# Boolean-based filter by response length
ffuf -c -w ~/code/guides/ctf/SecLists/Passwords/Leaked-Databases/rockyou-75.txt -u 'https://foo?FUZZ' -fs 123
ffuf -c -w ~/code/guides/ctf/SecLists/Passwords/Leaked-Databases/rockyou-75.txt -u 'https://foo?bar=FUZZ' -fs 234
```

- https://github.com/zaproxy/zap-extensions/tree/beta/src/org/zaproxy/zap/extension/bruteforce

### wordlists

- https://github.com/danielmiessler/SecLists
- https://github.com/allyshka/dirbustlist/tree/master/dirbuster
- https://github.com/zaproxy/zap-extensions/tree/master/addOns/directorylistv2_3/src/main/zapHomeFiles/fuzzers/dirbuster


