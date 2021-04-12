#!/bin/bash

# Decode
openssl x509 -in _ -noout -text
openssl x509 -inform pem -in _ -noout -text
openssl x509 -inform der -in _ -noout -text
while read -r l; do [ -n "$l" ] && [ "${l###}" = "$l" ] && printf '%s\n' "$l" | ssh-keygen -v -l -f /dev/stdin; done < authorized_keys

# Certificate mismatch
# => diff public keys
openssl rsa -pubout -in mydomain.key
openssl x509 -noout -pubkey -in mydomain.crt

# Certificate requested for ip
openssl req -new -newkey rsa:2048 -sha256 -nodes -out 1.1.1.1.ip.csr -keyout 1.1.1.1.key -config <(
cat <<-EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C=US
ST=California
L=Eureka
O=Acme Pen Testing
CN=1.1.1.1

[ req_ext ]
subjectAltName=@alt_names

[ alt_names ]
IP.1=1.1.1.1
DNS.1=1.1.1.1
EOF
)
