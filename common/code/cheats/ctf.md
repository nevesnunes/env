# ctf

https://github.com/teambi0s

https://github.com/ticarpi/jwt_tool

https://sudhackar.github.io/blog/INCTF-reversing-writeups
https://klanec.github.io/inctf/2020/08/02/inctf-lookout-foxy.html
https://spyclub.tech/2020/08/02/inctf2020-gosqlv3-challenge-writeup/
https://github.com/Az3z3l/XQLi/blob/master/solution.md
https://hackmd.io/@HKraw/r1yah4NbD

https://bitvijays.github.io/index.html

https://wiki.osdev.org/Tutorials
https://www.hacker101.com/sessions/native_code_crash_course

http://dann.com.br/shx7-for300-go_deeper/
https://github.com/ctfs/write-ups-2015/tree/master/camp-ctf-2015/forensics/APT-incident-response-400
https://dubell.io/securityfest-ctf-coresec-challenge-writeup/

CTF Tools of the Trade
https://book.hacktricks.xyz/
[disasm\.pro | Online Assembler and Disassembler](https://disasm.pro/)
https://hackertarget.com/wireshark-tutorial-and-cheat-sheet/
https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/

https://pentesterlab.com/exercises
https://github.com/w181496/Web-CTF-Cheatsheet
https://blog.p6.is/Web-Security-CheatSheet/
https://github.com/orangetw/My-CTF-Web-Challenges
munsiwoo---ctf-write-ups
terjanq---Flag-Capture
Web-Exploitation-Workflow

polyglots
```
https://twitter.com/filedescriptor/status/1289169647082672130

\\'\"><s>${{3-2}}

https://twitter.com/PortSwiggerRes/status/1289143670273462272

javascript:/*--></title></style></textarea></script></xmp><details/open/ontoggle='+/`/+/"/+/onmouseover=1/+/[*/[]/+alert(/@PortSwiggerRes/)//'>
```

https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
https://github.com/petoolse/petools

scapy
https://www.malware-traffic-analysis.net/training-exercises.html
https://www.malware-traffic-analysis.net/2020/index.html
https://ctf101.org/forensics/what-is-wireshark/#decrypting-ssl-traffic

[Online Javascript Editor](https://js.do/)

https://utf8-chartable.de/unicode-utf8-table.pl

https://2019.cybrics.net/tasks
https://github.com/tsg-ut/tsgctf2020
https://archive.ooo/

"SSL" traffic here isn't actually SSL traffic - Wireshark just thinks it is because it's port 443.
    https://github.com/poortho/ctf-writeups/tree/master/2020/uiuctf/friendship_gone_awry

sqli
```sql
-- %" UNION SELECT "one", "two"; --%";
-- %" AND username in (SELECT username FROM sqlite_master where username like "%") --

-- list tables / schemas
SELECT name, sql FROM sqlite_master WHERE type='table'
```

pwn
    http://eternal.red/2017/wiki-writeup/
    off-by-null
    write-what-where
    https://github.com/sajjadium/PersianCatsCTF
    https://github.com/sajjadium/CTFium
    https://heap-exploitation.dhavalkapil.com/
    https://github.com/TechSecCTF/pwn_challs
    https://github.com/Naetw/CTF-pwn-tips
    how2heap

pwntools
    ~/Downloads/faust2018-diagon-alley---client.py
    https://github.com/BigB00st/ctf-solutions/blob/master/rgbCTF/rev/time-machine/solve.py

relro
    https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html
rop
    https://ropemporium.com/guide.html
    https://www.youtube.com/watch?v=GTQxZlr5yvE
    https://malwaresec.github.io/Stack-Based-Buffer-Overflow/
    https://amriunix.com/post/sigreturn-oriented-programming-srop/
    https://thisissecurity.stormshield.com/2015/01/03/playing-with-signals-an-overview-on-sigreturn-oriented-programming/
    https://github.com/5h3r10ck/CTF_Writeups/tree/master/H%40ctivitycon_writeups/Statics_and_Dynamics

privilesge escalation
    https://gtfobins.github.io

golang, pin
    http://eternal.red/2017/dont_panic-writeup/

gdb scripts
    http://rce4fun.blogspot.com/2017/11/hxp-ctf-2017-dontpanic-reversing-100.html
    https://ctftime.org/writeup/7519
    https://bannsecurity.com/index.php/home/10-ctf-writeups/36-openctf-2016-neophyte-reversing
    https://github.com/ctfs/write-ups-2016/tree/master/open-ctf-2016/reversing/neophyte-reversing-200

unicorn emulator
    ! reimplement f-hash - https://ctftime.org/task/10861
    deobfuscator
        https://wiki.jaxhax.org/index.php/Keystone,_Capstone,_and_Unicorn_Engines#Code_Example:_deobfuscate_x86_payload.py
        https://unit42.paloaltonetworks.com/unit42-pythons-and-unicorns-and-hancitoroh-my-decoding-binaries-through-emulation/
    mem reader
        https://github.com/mothran/unicorn-decoder/blob/master/decoder.py
    http://eternal.red/2018/unicorn-engine-tutorial/
    https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/sample_x86.py
    https://github.com/v-p-b/ripr/blob/c9c7d3c3166493ba9b21bec627c5109f9477c5da/sample/rc4/prga.py
    https://github.com/unicorn-engine/unicorn/issues/731

https://web.archive.org/web/20170703044113/http://uwctf.cs.washington.edu/writeups/google-ctf-2017/inst-prof/
    rop
https://klatz.co/ctf-blog/boilerctf-alien-tech
https://teamrocketist.github.io/2019/12/30/Reverse-36c3-xmas-future/
    wasm

https://github.com/michalmalik/linux-re-101
    https://syscalls.w3challs.com/
    https://man7.org/linux/man-pages/man2/syscall.2.html
        register conventions

```bash
file -k
strings

# instruction counting
gcc -O0 a.c && echo 'a' | perf stat -e instructions:u ./a.out 2>&1 | awk '/instructions.u/{print $1}'
~/opt/dynamorio/build/bin64/drrun -c ~/opt/dynamorio/build/api/bin/libinscount.so -- ./a.out | awk '/Instrumentation results:/{print $3}'
qemu-x86_64 -d in_asm ~/a.out 2>&1 | awk '/IN:/{i+=1} END{print i}'
    # https://en.wikibooks.org/wiki/QEMU/Invocation
# [Counting instructions using Stalker · Issue \#94 · frida/frida\-python · GitHub](https://github.com/frida/frida-python/issues/94)
# https://stackoverflow.com/questions/22507169/how-to-run-record-instruction-history-and-function-call-history-in-gdb
# https://stackoverflow.com/questions/8841373/displaying-each-assembly-instruction-executed-in-gdb/46661931#46661931

# coverage
~/opt/dynamorio/build/bin64/drrun -t drcov -dump_text -- ./a.out
    diff -Nauw drcov.a.out.2575073.0000.proc.log drcov.a.out.2575098.0000.proc.log | vim -
    # https://dynamorio.org/dynamorio_docs/page_drcov.html
# https://stackoverflow.com/questions/53218160/how-can-i-do-code-path-analysis-in-a-debugger
```

http://shell-storm.org/blog/A-binary-analysis-count-me-if-you-can/
~/code/snippets/pin/

for a given competition, try challenges from previous years

f .md | xargs -i grep -li ' z3' {}

https://ascii.cl/htmlcodes.htm

```bash
pip3 install flask-unsign
flask-unsign --sign --cookie "{'end': '2020-07-13 10:59:59+0000'}" --secret 'Time' --legacy
```

radio transmissions
    http://manpages.ubuntu.com/manpages/focal/en/man1/multimon.1.html

https://sshell.co/ctf/2020/07/13/rbgctf-2020-writeups/#adventure
    Any time there are customized/edited assets inside a game, I try to “work backwards” and think of what sort of tools are out there to do this specific thing. 
https://isopach.dev/rgb-CTF-2020/#keen-eye
    There was a cdn link to a suspicious JS called poppers.min.js. The usual package is popper.min.js so there was an extra s in there.

https://github.com/spitfirerxf/rgbCTF2020/tree/master/PI1
    [convert all keypresses and turn to HEX codes ready for BLE / AT Commands · GitHub](https://gist.github.com/willwade/30895e766273f606f821568dadebcc1c#file-keyboardhook-py-L42)
https://github.com/signifi3d/ctf-writeups/blob/master/rgbCTF2020/osint/p1/p1.md
    Filter ATT packets: "btl2cap.cid==0x004"
https://github.com/greatscottgadgets/libbtbb
https://learn.adafruit.com/introducing-bluefruit-ez-key-diy-bluetooth-hid-keyboard/sending-keys-via-serial
     Raw USB HID keycodes

https://github.com/mdsnins/ctf-writeups/blob/master/2020/TSGCTF/Beginners%20Web/beginners_web.md
https://github.com/dobsonj/ctf/tree/master/writeups/2020/rgbctf/advanced_reversing_mechanics_2
https://github.com/BigB00st/ctf-solutions/blob/master/rgbCTF/rev/advanced-reversing-mechanics-2/solve.py

---

https://portswigger-labs.net/hackability/inspector/index.php?input=window
https://hack.more.systems/writeup/2014/10/26/hacklu2014-objection/

https://mathiasbynens.be/notes/javascript-escapes

[JS NICE: Statistical renaming, Type inference and Deobfuscation](http://jsnice.org/)

https://github.com/w181496/Web-CTF-Cheatsheet#%E7%A9%BA%E7%99%BD%E7%B9%9E%E9%81%8E
/Hello W/.source+/ordl!/.source == "Hello World!"

[Day 1 — CyBRICS Task Analysis Session \- YouTube](https://www.youtube.com/watch?v=3tq1o8wBqJ0)
https://dreadlocked.github.io/2018/10/08/nn8ed-tindermon-writeup/
[CTFtime\.org / Harekaze CTF 2019 / /\(a\-z\(\)\.\)/ / Writeup](https://ctftime.org/writeup/15376)
https://dttw.tech/posts/S1R4BzXzQ
https://corb3nik.github.io/blog/ins-hack-2019/bypasses-everywhere
https://sectt.github.io/writeups/BACKDOORCTF19/notes-app/README
https://0day.work/boston-key-party-ctf-2016-writeups/
https://hxp.io/blog/61/Balsn-CTF-2019-writeups/
[CTFtime\.org / Newbie CTF\(N\-CTF\) 2019 / python\_jail / Writeup](https://ctftime.org/writeup/17085)
[CTFtime\.org / ASIS CTF Quals 2018 /  Buy flags  / Writeup](https://ctftime.org/writeup/9913)
https://bananamafia.dev/post/cryptoctf-1-decodeme/

cmd = '''
python -c "__import__('time').sleep({} if open('/home/nullcon/flagpart1.txt').read({})[-1:] == '{}' else 0)"
'''.format(SLEEP_TIME, index, letter)

https://www.reddit.com/r/ReverseEngineering/comments/grmxs4/how_to_just_emulate_it_with_qemu_a_guide_to/
    https://www.zerodayinitiative.com/blog/2020/5/27/mindshare-how-to-just-emulate-it-with-qemu

```
-->'"/></sCript><deTailS open x=">" ontoggle=(co\u006efirm)``>

-->          Breaks comment context
'            Breaks Attribute Context
"            Breaks attribute context
/>           Closes an open tag
</sCript>    Breaks JS context
<deTailS     A less known tag
open         To eliminate user interaction required for execution
x            Dummy attribute
">"          Mimics the closing of tag
ontoggle     A less known event handler
()           Parentheses around the function
co\u006efirm "confirm" function with Unicoded 'n'
``           Backticks instead of ()
```

hashing
https://github.com/rpm0618/writeups/blob/master/uiuctf2020/login_page/README.md
https://sshell.co/ctf/2020/07/20/uiuctf-2020-writeups/#login_page
```
hashcat.exe 530bd2d24bff2d77276c4117dc1fc719 -a 3 ?d?d?d-?d?d?d-?d?d?d?d
-a 3 - mask attack
    https://hashcat.net/wiki/doku.php?id=mask_attack
hashcat.exe 4106716ae604fba94f1c05318f87e063 -m 2600 -a 3 10?d?d?d?d?d?d?d?d?d?d
-m 2600 - run md5 twice
    https://hashcat.net/wiki/doku.php?id=hashcat

.\hashcat.exe -O .\hashes.txt --hex-charset -a 3 -1 d8d9 -2 8182838485868788898aa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf '?1?2?1?2?1?2?1?2?1?2?1?2'
||
hashcat -m 0 -a 3 --hex-charset -1 d8d9dadb -2 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf -o output hashes "?1?2?1?2?1?2?1?2?1?2?1?2"
    https://blog.bitcrack.net/2013/09/cracking-hashes-with-other-language.html
    https://utf8-chartable.de/unicode-utf8-table.pl?start=1536
    https://deadpixelsec.com/Hashcat-on-Google-Colab

should have a much smaller estimate
in particular i kept gradually expanding "arabic letter"
assuming the arabic word for cat does not have non-letters in the word
an alternative would be to use a charset file instead of the two-byte approach to arabic (although i'm not sure if charset file actually reads unicode codepoints)
that brings the search space from 256^6 to around 80^6 or something
because not all combinations of ?1?2 are actual arabic

.\hashcat.exe -a 1 -m 0 58970d579d25f7288599fcd709b3ded3 chars3.txt chars3.txt -O

where chars3 was created with .\combinator3.exe chars.txt chars.txt chars.txt and chars.txt was a list of all arabic letters

I don't know if it is correct, but I modified the above to exclude characters with the word WITH in them (like ARABIC LETTER ALEF WITH HAMZA ABOVE).  This generates only 80 candidates and, after combining etc..., that cracks in 2 mins.

import sys
import unicodedata

for i in range(0x600, 0x700):
    c = chr(i)
    category = unicodedata.category(c)
    name = ''
    try :
        name = unicodedata.name(c)
    except:
        pass
    if category == 'Lo' and ' WITH ' not in name:
        cb = c.encode('utf-8')
        sys.stdout.buffer.write(cb + b"\n")
```

xss
https://terjanq.me/xss.php?js=onhashchange=setTimeout;Object.prototype.toString=RegExp.prototype.toString;Object.prototype.source=location.hash;location.hash=null;#1/-alert(location.href)/
```javascript
onhashchange=setTimeout;
Object.prototype.toString=RegExp.prototype.toString;
Object.prototype.source=location.hash;
location.hash=null
```
Explanation:
* onhashchange passes an object to setTimeout
* Regex.prototype.toString returns a string /[source]/[flags]
* Object.prototype.toString=Regex.prototype.toString
* Object.prototype.source = '#1/-alert(location.href)/'
* {}.toString() prints /#1/-alert(location.href)//
* setTimeout(object) casts an object to string and evaluates it 
It's similar to onerror=eval technique by @garethheyes, but is universal over different browsers


