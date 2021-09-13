#!/usr/bin/env python3

import blackboxprotobuf
import os
import pprint
import sqlite3
import sys

filename = sys.argv[1]
with sqlite3.connect(filename) as conn:
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()    
    cursor.execute("SELECT ZMAPITEMSTORAGE FROM ZMIXINMAPITEM WHERE ZFAVORITEITEM not null")
    for row in cursor.fetchall():
        blob = row[0]
        with open('blob', 'wb') as out:
            out.write(blob)
        msg, msg_typedef = blackboxprotobuf.decode_message(blob)
        pprint.pprint(msg, indent=4)
        pprint.pprint(msg_typedef, indent=4)
