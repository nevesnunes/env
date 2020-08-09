# Generate key pair

```bash
ssh-keygen -t ecdsa -b 4096 -C "your_email@example.com"
ssh-keygen -t ed25519 -f ~/.ssh/foo

# References:
# - https://security.stackexchange.com/questions/50878/ecdsa-vs-ecdh-vs-ed25519-vs-curve25519
# - https://support.solarwinds.com/SuccessCenter/s/article/Converting-OpenSSH-and-PuTTY-style-keys

id='foo_user@foo_host' && \
    ssh-keygen -b 2048 -t rsa -f ~/.ssh/"$id" -q -C "" -N ""
# ||
# Select: Type of key to generate = RSA
# Select: Save private key
# Copy public key manually to .pub file
id='foo_user@foo_host' && \
    ~/opt/putty/PUTTYGEN.EXE ~/.ssh/"$id" -O private -o ~/.ssh/"$id".ppk

id='foo_user@foo_host' && \
    ssh-copy-id -i ~/.ssh/"$id".pub "$id"

# || On ssh server host:
mkdir -p ~/.ssh/
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
printf 'ssh-rsa AAAA/.../ZZZZ' >> ~/.ssh/authorized_keys
# ||
cat ~/.ssh/"$id".pub >> ~/.ssh/authorized_keys
```

# Better performance

```bash
# Requires: SSH server with sftp support
sshfs -o Ciphers=arcfour -o Compression=no server://some_folder /mnt/some_local_folder
rsync -e"ssh -c arcfour -o Compression=no"

# Requires: SSH server with `AllowTCPPortForwarding` disabled
local_port=
remote_host=
remote_port=
socat TCP-LISTEN:$local_port,reuseaddr,fork "EXEC:ssh $remote_host nc localhost $remote_port"
```

# scp permissions

```bash
# [client]
scp foo@bar:/a/b/*
unable to identify /a/b: permission denied
# [server]
chmod 755 /a/b
```

# plink

Debug with pseudo terminal: `-t`

http://www.straightrunning.com/puttymanual/Chapter7.html#plink-option-antispoof

# pscp

```ps1
$id='foo_user@foo_host';
$dir='\\foo';
cd ${dir};
& ${dir}\opt\putty\pscp -i ${dir}\.ssh\foo.ppk -r ${id}:/tmp/foo .
```

# Debug - Login script at the remote end produce garbage on stdout

```bash
ssh foo_user@foo_pass /bin/true | xxd
```

# Validation

Requires `Subject Alternative Name`

https://wiki.openssl.org/index.php/Hostname_validation
=> CN or alt

hostname conditional
https://stackoverflow.com/a/33555404

DNS resolves to a different IP (internal address) that does not contain a valid certificate chain (no trusted CA anchor, no valid hostname, missing SAN)
    workaround - request to the outside IP from inside the network

# bastion

```
# disable sftp subsystem
# disable tty allocation
# shell = /bin/false
Match User bastion
      AllowAgentForwarding yes
      AllowTcpForwarding yes
      AllowStreamLocalForwarding no
      PermitTunnel no
      PermitTTY no
      X11Forwarding no
      ForceCommand /bin/false
```

https://docs.pritunl.com/docs/bastion-ssh-host

# proxy

https://ma.ttias.be/socks-proxy-linux-ssh-bypass-content-filters/

# powershell integration

https://blog.netnerds.net/2017/12/updated-ssh-tunneling-for-windows-people-protecting-remote-desktop/

# Implementations

Supercedes: telnet, rsh

On Windows:
https://github.com/billziss-gh/sshfs-win
    net use \\sshfs\USER@HOST[\PATH]
    https://github.com/billziss-gh/sshfs-win/issues/98
    https://github.com/billziss-gh/sshfs-win/issues/33
    https://github.com/billziss-gh/winfsp
https://github.com/feo-cz/win-sshfs
    csharp, inactive

# References

https://developer.android.com/training/articles/security-ssl.html#CommonHostnameProbs
[RFC 5280 \- Internet X\.509 Public Key Infrastructure Certificate and Certificate Revocation List \(CRL\) Profile](https://tools.ietf.org/html/rfc5280)

https://stackoverflow.com/questions/2308774/httpget-with-https-sslpeerunverifiedexception
https://github.com/vt-middleware/ldaptive/blob/master/core/src/main/java/org/ldaptive/ssl/DefaultHostnameVerifier.java
