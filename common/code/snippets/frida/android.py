#!/usr/bin/env python3

import frida
import time
import sys

js = """
Java.perform(function() {
       var mainActivity = Java.use("re.rada.con.ctf.r2xor.MainActivity");
       mainActivity.n.implementation = function() {
           console.log("[*] Root check called");
           return false;
        }
       console.log("[+] Hooking complete")
})
"""


def on_message(message, data):
    print(message)


device = frida.get_usb_device()
pid = device.spawn(['re.rada.con.ctf.r2xor'])
print("[+] Got PID %d" % (pid))
session = device.attach(pid)
script = session.create_script(js)

# Callback function
script.on('message', on_message)
script.load()

device.resume(pid)

sys.stdin.read()
print("[!] Exiting")
