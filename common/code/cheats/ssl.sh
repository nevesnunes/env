#!/bin/sh

# Decode
openssl x509 -in _ -noout -text
openssl x509 -inform pem -in _ -noout -text
openssl x509 -inform der -in _ -noout -text

# Certificate mismatch
# => diff public keys
openssl rsa -pubout -in mydomain.key
openssl x509 -noout -pubkey -in mydomain.crt
