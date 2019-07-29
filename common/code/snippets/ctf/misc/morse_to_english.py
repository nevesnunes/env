
#From https://gist.github.com/ebuckley/1842461

morseAlphabet ={
  "A" : ".-",
  "B" : "-...",
  "C" : "-.-.",
  "D" : "-..",
  "E" : ".",
  "F" : "..-.",
  "G" : "--.",
  "H" : "....",
  "I" : "..",
  "J" : ".---",
  "K" : "-.-",
  "L" : ".-..",
  "M" : "--",
  "N" : "-.",
  "O" : "---",
  "P" : ".--.",
  "Q" : "--.-",
  "R" : ".-.",
  "S" : "...",
  "T" : "-",
  "U" : "..-",
  "V" : "...-",
  "W" : ".--",
  "X" : "-..-",
  "Y" : "-.--",
  "Z" : "--..",
  "0" : "-----", 
  "1" : ".----", 
  "2" : "..---", 
  "3" : "...--", 
  "4" : "....-", 
  "5" : ".....", 
  "6" : "-....", 
  "7" : "--...", 
  "8" : "---..", 
  "9" : "----.", 
  " " : "/"
}

inverseMorseAlphabet=dict((v,k) for (k,v) in morseAlphabet.items())


#testCode = ".... . .-.. .-.. --- / -.. .- .. .-.. -.-- / .--. .-. --- --. .-. .- -- -- . .-. / --. --- --- -.. / .-.. ..- -.-. -.- / --- -. / - .... . / -.-. .... .- .-.. .-.. . -. --. . ... / - --- -.. .- -.-- "
testCode = "-... --. ---.. -.... --. ---.. ....- .-. --. .-.. .- ...- -.- --. .-.. ..- .-- -. ..... . .... ....- -. --. .... -.... --... ....- .-- ...- -. ..- -.-. -.... -.. .-.. -... -.-- --... -.- -- -- --.. -. ..... .- - ..... ----- ----. .- ..- --.- .---- . .... .. . .--. ...-- ..... -.. .... ....- .. ...- - ...-- -.-- ..-. -- .-.. .--. --.- .. .-.. -.... ...-- ...-- --... ----. --... ..- .. ..- --. --. -... -... ..--- ..... ..-. ..--- .-- .-. - .---- -.- -..- .-."



def decode_morse(morse_code):
    return ''.join(inverseMorseAlphabet[code] for code in morse_code.split())
        
#encode a message in morse code, spaces between words are represented by '/'
def encodeToMorse(message):
  encodedMessage = ""
  for char in message[:]:
    encodedMessage += morseAlphabet[char.upper()] + " "
                
  return encodedMessage + '\n'


if __name__ == "__main__":
#  english = decode_morse(testCode)
#  print(english)

#  print(int("1KGV0QZPGVYT94IP", 36))

  import socket
  
  port=11821
  url="morset.pwning.xxx"
  socket = socket.socket()
  socket.connect((url,port))

  # Their greet
  rcv = socket.recv(1024)
  rcv = rcv.decode("utf-8")
  print("[+] Greet: {}".format(rcv))
  morse_dec = decode_morse(rcv.strip()) + '\n'
  print("[+] Greet in alphanum: {}".format(morse_dec))
  print("[+] Greet length: {}".format(len(morse_dec)))

  # Our message
  '''
  msg = ".-"
  for x in range(0, 2):
    msg += " .-"
  msg += "\n"
  '''
  msg = encodeToMorse("hello")
  socket.send("hello\n")
  print("[+] Sending: {}".format(msg))

  # Skip
  rcv = socket.recv(1024)
  rcv = rcv.decode("utf-8")
  print("[+] Skip: {}".format(rcv))

  # Their answer
  rcv = socket.recv(1024)
  rcv = rcv.decode("utf-8")
  print("[+] Answer: {}".format(rcv))
  morse_dec = decode_morse(rcv.strip()) + '\n'
  print("[+] Answer in alphanum: {}".format(morse_dec))
  print("[+] Answer length: {}".format(len(morse_dec)))

'''
  morse_en = decode_morse(rcv.strip()) + '\n'
  morse_en = morse_en.encode()
  socket.send(morse_en)
  print("[+] Sending {}".format(morse_en))
'''
