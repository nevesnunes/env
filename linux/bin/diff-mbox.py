#!/usr/bin/env python3

import hashlib
import mailbox
import sys


def extract_body(message):
    body = None
    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart():
                for subpart in part.walk():
                    if subpart.get_content_type() == "text/plain":
                        body = subpart.get_payload()
                        break
            elif part.get_content_type() == "text/plain":
                body = part.get_payload()
                break
        if not body:
            body = message.get_payload()[0]
    if not body:
        body = message.get_payload()

    if isinstance(body, str):
        try:
            return body.encode("utf8")
        except UnicodeEncodeError:
            return body.encode("latin-1")
    else:
        return body


def extract_id(message):
    message_id = message.get("Message-ID")
    if message_id:
        return message_id
    else:
        return hashlib.sha1(extract_body(message)).hexdigest()


def extract_ids(mbox):
    ids = []
    for message in mbox:
        ids.append(extract_id(message))
    return ids


def diff(mbox, ids):
    is_skipping = False
    for message in mbox:
        message_id = extract_id(message)
        message_date = message.get("Date")
        if not message_date:
            if not is_skipping:
                is_skipping = True
                print("Skipping:", end="")
            print(".", end="")
            return
        if message_id not in ids:
            if is_skipping:
                is_skipping = False
                print("")
            print(message_date, extract_body(message))


f1 = sys.argv[1]
f2 = sys.argv[2]
print(f"Parsing {f1}...")
mbox_1 = mailbox.mbox(sys.argv[1])
print(f"Parsing {f2}...")
mbox_2 = mailbox.mbox(sys.argv[2])
print(f"Extracting ids from {f1}...")
mbox_1_ids = extract_ids(mbox_1)
print(f"Extracting ids from {f2}...")
mbox_2_ids = extract_ids(mbox_2)
print(f"Diffing {f1} against ids from {f2}...")
diff(mbox_1, mbox_2_ids)
print(f"Diffing {f2} against ids from {f1}...")
diff(mbox_2, mbox_1_ids)
