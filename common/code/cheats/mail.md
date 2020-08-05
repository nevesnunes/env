# Read Mailbox

### IMAP

```bash
telnet imap-mail.outlook.com imap
```

> Trying 40.101.92.2...  
> Connected to imap-mail.outlook.com.  
> Escape character is '^]'.  
> \* OK The Microsoft Exchange IMAP4 service is ready. [TQBSADIAUAAyADYANABDAEEAMAAwADIAOQAuAEYAUgBBAFAAMgA2ADQALgBQAFIATwBEAC4ATwBVAFQATABPAE8ASwAuAEMATwBNAA==]  
> 1 CAPABILITY  
> \* CAPABILITY IMAP4 IMAP4rev1 LOGINDISABLED STARTTLS SASL-IR UIDPLUS ID UNSELECT CHILDREN IDLE NAMESPACE LITERAL+  
> 1 OK CAPABILITY completed.  

```bash
# -debug: List certificate, hex dump
openssl s_client -debug -4 -crlf -ign_eof -connect imap-mail.outlook.com:993
env u=fmn_nunes@netcabo.pt p=zbd-master.9341 echo -en "1 LOGIN $u $p\n$(echo -en "\0$u\0$p" | base64)\n"
```

> [...]  
> 1 CAPABILITY  
> \* CAPABILITY IMAP4 IMAP4rev1 AUTH=PLAIN AUTH=XOAUTH2 SASL-IR UIDPLUS ID UNSELECT CHILDREN IDLE NAMESPACE LITERAL+  
> 1 OK CAPABILITY completed.  
> 1 LOGIN foo@bar.com baz  
> [...]  
> 1 OK LOGIN completed.  
> 2 LIST "" "*"  
> [...]  
> 3 EXAMINE INBOX  
> [...]  
> 4 FETCH 1 BODY[]  
> [...]  
> 5 LOGOUT  

- [RFC 3501 \- INTERNET MESSAGE ACCESS PROTOCOL \- VERSION 4rev1](https://tools.ietf.org/html/rfc3501#section-6)
    - 6\. Client Commands

### POP3

> USER foo  
> [...]  
> PASS bar  
> [...]  
> LIST  
> [...]  
> RETR message_number  
> [...]  
> QUIT  

- [RFC 1939 \- Post Office Protocol \- Version 3](https://tools.ietf.org/html/rfc1939)

### Outlook issues

> 2 LIST "" "*"  
> [...]  
> 2 BAD User is authenticated but not connected.  

https://web.archive.org/web/20141003094632/http://blog.sanebox.com/post/87985445280/office365-authentication-is-broken-and-insecure

# Authentication

```bash
base64_credentials=$(printf '\x00%s\x00%s' "foo@bar.com" "password" | base64)
```

> 2 AUTHENTICATE PLAIN  
> [...]  
> +  
> base64_credentials  
> 2 OK AUTHENTICATE completed.  

- [RFC 2595 \- Using TLS with IMAP, POP3 and ACAP](https://tools.ietf.org/html/rfc2595#section-6)
    - 6\. PLAIN SASL mechanism

# Encryption

- [RFC 5246 \- The Transport Layer Security \(TLS\) Protocol Version 1\.2](https://tools.ietf.org/html/rfc5246#section-7.4.2)
    - Server Certificate
- [RFC 4492 \- Elliptic Curve Cryptography \(ECC\) Cipher Suites for Transport Layer Security \(TLS\)](https://tools.ietf.org/html/rfc4492#section-2)
    - Key Exchange Algorithms
        > ECDH_ECDSA          Fixed ECDH with ECDSA-signed certificates.  
        > ECDHE_ECDSA         Ephemeral ECDH with ECDSA signatures.  
        > ECDH_RSA            Fixed ECDH with RSA-signed certificates.  
        > ECDHE_RSA           Ephemeral ECDH with RSA signatures.  
        > ECDH_anon           Anonymous ECDH, no signatures.  
