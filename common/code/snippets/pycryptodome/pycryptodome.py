#!/usr/bin/env python3

import base64
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

ENCODING = 'utf-8'
encrypted_data = 'foo'.encode(ENCODING)
encrypted_data = b'S\xacU\x14\xb2E\xec\x08\xc3\x83\x18\x8ey\x98\x069'
key = RSA.import_key(open('private.pem').read())
raise ValueError(type(key))
pub_key_new = RSA.import_key(open('private.pub').read())


def get_signature(message):
    h = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(h)
    return signature


EncryptedString = base64.standard_b64encode(encrypted_data).decode(ENCODING)

SignedDataString = base64.standard_b64encode(get_signature(encrypted_data)).decode(ENCODING)


def verify_signature(message, signature):
    h = SHA256.new(message)
    try:
        pkcs1_15.new(pub_key_new).verify(h, signature)
        print("The signature is valid.")
    except (ValueError, TypeError) as e:
        print("The signature is not valid.")
        print(e)


verify_signature(base64.standard_b64decode(EncryptedString), base64.standard_b64decode(SignedDataString))
