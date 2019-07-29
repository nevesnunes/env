#!/usr/bin/python

from struct import *
import zlib

allLines = open('steg.png').read()
print "length = " , len(allLines)

pos=0

print "sig:",
tmp=unpack('cccccccc',allLines[pos+0:pos+8])
pos+=8
print tmp

print "1st chunk(",pos,"):"

tmp=unpack('!I',allLines[pos+0:pos+4])
pos+=4
print "  size = " , tmp
size=tmp[0]
print "  size = " , size

tmp=unpack('cccc',allLines[pos+0:pos+4])
pos+=4
print "  " , tmp

print "  payload: " ,
ii=0

while ii < size:
    tmp=allLines[pos:pos+1]
    pos+=1
    ii+=1
    # print unpack('c',tmp)[0],
    print hex(ord(tmp)),
print

tmp=unpack('cccc',allLines[pos+0:pos+4])
pos+=4
print "  CRC: " , tmp

print "2nd chunk(",pos,"):"

tmp=unpack('!I',allLines[pos+0:pos+4])
pos+=4
print "  size = " , tmp
size=tmp[0]
print "  size = " , size

tmp=unpack('cccc',allLines[pos+0:pos+4])
pos+=4
print "  " , tmp


tmp_def=allLines[pos+0:pos+size]
print "  length = " , len(tmp_def)
pos=pos+size

tmp=unpack('cccc',allLines[pos+0:pos+4])
pos+=4
print "  CRC: " , tmp

print "3rd chunk(",pos,"):"

tmp=unpack('!I',allLines[pos+0:pos+4])
pos+=4
print "  size = " , tmp
# size=tmp[0]
# print "  size = " , size

tmp=unpack('cccc',allLines[pos+0:pos+4])
pos+=4
print "  " , tmp


tmp2=zlib.decompress(tmp_def)
print "data length in PNG file: ", len(tmp_def)
print "decompressed data length: ", len(tmp2)

print "800 x {800 x 3 + 1} = ", 800*(800*3+1)
# http://hoshi-sano.hatenablog.com/entry/2013/08/18/113434

j=0
tmp3=[]
while j < len(tmp2)/2401:
    tmp=unpack('2401c',tmp2[j*2401:(j+1)*2401])
    # print " j=",j,ord(tmp[0])
    # print ord(tmp[0]),
    tmp3.append(ord(tmp[0]))
    # tmp3[len(tmp3)]=ord(tmp[0])
    # ans[j]=ord(tmp[0])
    j+=1

print tmp3
print "length=",len(tmp3)

i=0; j=0;
# ch=0
# ch="00000000"; 
ch=""
ch2=0
ans=""
while i < len(tmp3):
    # print "bit = ",tmp3[i]
    ch=ch + str(tmp3[i])
    ch2+=tmp3[i]*2**j
    j+=1
    i+=1
    if j == 8:
        j=0
        print "ch=",ch , ch2, chr(ch2)
        if ch2 != 0:
            ans = ans + chr(ch2)
        ch=""
        ch2=0

print "ans = " , ans
