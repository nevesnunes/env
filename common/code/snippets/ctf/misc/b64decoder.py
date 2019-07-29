import base64

data = "xquGE3rx5jFdiGN4Jn_T5iKSJ2X0LgXiOv5lPSpzCEI="
b64 = data.decode('base64')
print b64
print base64.b64decode(data)
