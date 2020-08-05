# log pid

### firewall

```bash
# Firewall managed ports
iptables -I INPUT -p tcp --dport some_port --jump LOG --log-level DEBUG

# Only new connection attempts
iptables -I INPUT -p tcp --dport some_port -m state --state NEW

# Validation
tail -f /var/log/messages
```

### auditd

```bash
# Enable
auditctl -a exit,always -F arch=b64 -S connect -k MYCONNECT

# Disable
auditctl -d ...

# Validation
ausearch -i
```

https://serverfault.com/questions/352259/finding-short-lived-tcp-connections-owner-process
    https://www.daemon.be/maarten/auditd.html

### ip_conntrack

```bash
modprobe ip_conntrack
cat /proc/net/ip_conntrack
```

### SELinux managed ports

```bash
semanage port -l

# Validation
tail -f /var/log/audit/audit.log
```

### polling

```bash
while true; do
  netstat -an | grep ESTABLISHED
  sleep 0.1
done

cat /proc/net/tcp
# Take `inode`, iterate through pids and fds until found
readlink /proc/$pid/fd/$fd
```

https://superuser.com/questions/34782/with-linux-iptables-is-it-possible-to-log-the-process-command-name-that-initiat

# network bandwidth / throughput

```bash
# server
nc -l -p 12345 | wc -c

# client
dd if=/dev/zero bs=1024K count=512 | nc -q 0 $server_ip 2222

# dd output
# 536870912 bytes (537 MB) copied, 4.87526 s, 117 MB/s

# || tune timing, buffers and protocols
iperf -s
iperf -i 1 -c $server_ip
```

https://iperf.fr/
    https://fasterdata.es.net/performance-testing/network-troubleshooting-tools/iperf/

# network segmentation, private VLANs, intra/inter VLAN ACLs

https://medium.com/@cryps1s/endpoint-isolation-with-the-windows-firewall-462a795f4cfb
IPSEC gives you kerberos authentication out of the gate. Use it. Build AD groups for your tier 0/tier 1 administrators and machines.
Enforce bastion hosts with MFA.
Use ASR for neutering WMI calls. 
Available in GPO and MEM, auditing exists.

# DNS

caching - based on zone reported TTLs
    https://superuser.com/questions/1533833/how-are-dns-records-updated-to-all-dns-servers-in-the-internet

DynDNS
    https://dyn.com/

# sequence diagram

Wireshark > Statistics > Flow Graph
https://github.com/fran-ovia/pcap2puml-py
https://github.com/dgudtsov/pcap2uml
https://sourceforge.net/projects/callflow/

# ARP spoofing

~/code/snippets/arp_spoof.py

# +

https://wiki.wireshark.org/Tools

SYN and ACK bits sent and received in both directions

tls
1. client hello - cipher suites supported
2. server hello - cipher suite selected
3. server certificate - authentication
    Packet Details > Handshake Protocol: Certificate > Export Packet Bytes...
4. server symmetric keys exchange, e.g. Diffie-Helman - confidentiality for secure stream
    wireshark - filter = ssl, follow = ssl stream
    https://community.cisco.com/t5/security-documents/troubleshoot-tls-using-wireshark/ta-p/3396123
    https://crypto.stackexchange.com/questions/19203/diffie-hellman-and-man-in-the-middle-attacks
on non-standard port
    Packet List > Decode As...

capture setup
    Npcap || Win10Pcap
        https://nmap.org/npcap/vs-winpcap.html
    Wireshark Legacy - skips interface verification
    https://wiki.wireshark.org/CaptureSetup/InterferingSoftware
        Cisco VPN client: may hide all packets, even if not connected - disable the firewall in the Cisco VPN client or stop the "Cisco Systems, Inc. VPN Service"

https://blogs.technet.microsoft.com/nettracer/2010/10/01/how-to-decrypt-an-ssl-or-tls-session-by-using-wireshark
https://blogs.technet.microsoft.com/nettracer/2013/10/12/decrypting-ssltls-sessions-with-wireshark-reloaded/
    Decrypt with private key
        Edit > Preferences > Protocols > SSL > RSA keys list
            IP, Port - from host that holds the private key used to decrypt the data and serves the certificate (i.e. the decrypting host, the server)
            Protocol - upper-layer protocol encrypted by SSL/TLS, e.g. the protocol encrypted over a HTTPS connection is HTTP
            SSL debug file = C:\Temp\ssl_debug.txt
        :( If a Diffie-Hellman Ephemeral (DHE) or RSA ephemeral cipher suite is used, the RSA keys are only used to secure the DH or RSA exchange, not encrypt the data.
            Cipher Suite = TLS_DHE, SSL_DHE
            ServerKeyMessage
        :( Capture must include SSL/TLS session establishment
            Server sends certificate
            SSL debug file = `ssl_restore_session can’t find stored session`
        :( Duplicate packets
            editcap -d
        https://packetpushers.net/using-wireshark-to-decode-ssltls-packets/
        https://www.ibm.com/developerworks/web/tutorials/wa-tomcat/index.html
    Decrypt without private key
        File > Export SSL Session Keys...
    Packet list
        Before = tcp
        After = tcp, http, ssl, tls
    Packet details > Expand: "Hypertext Transfer Protocol", "Line-based text data: text/html"
    Print > Packet Format > Packet details = As displayed

Termination of TCP connection = encrypted alert, SSL_shutdown
    https://osqa-ask.wireshark.org/questions/38050/tlsv1-record-layer-encrypted-alert
    https://www.openssl.org/docs/ssl/SSL_shutdown.html
    https://tools.ietf.org/html/rfc5246#page-29

Certificate Requirements for TLS
    Version = V3
    Enhanced Key Usage = Server Authentication OID
    Subject = Server FQDN
    Subject Alternative Name = Server DNS FQDN
    Public Key = RSA
    Key Usage = "Digital Signature", "Key Encipherment"
    https://documentation.meraki.com/zGeneral_Administration/Other_Topics/Certificate_Requirements_for_TLS
    https://support.microsoft.com/en-my/help/814394/certificate-requirements-when-you-use-eap-tls-or-peap-with-eap-tls

Local network is untrustworthy, cannot confirm it is connected to secure gateway, unknown CA
    http://blog.bstpierre.org/fixing-certificate-errors-with-cisco-anyconnect
    ```bash
    vpn_server=
    openssl s_client -connect www."$vpn_server".com:443 2>&1 | sed -n '/^issuer=/s/.*CN=//p'
    # Given CA name, download input.crt
    # || Use keystore:
    # cp $(dpkg -L ca-certificates | grep -i thawte) /tmp/certificate-conversion/
    # || Copy all global certificates
    # sudo cp /etc/ssl/certs/cd /etc/ssl/cert/* /opt/.cisco/certificates/ca
    openssl x509 -in input.crt -out input.der -outform DER
    openssl x509 -in input.der -inform DER -out output.pem -outform PEM
    cp output.pem ~/.cisco/certificates/ca
    ```

User Authentication against Active Directory, Dissecting EAP-TLS
    SAM Account Name (short name) vs User Principle Name (UPN, includes domain)
    ~/Downloads/BRKSEC-3229.pdf


