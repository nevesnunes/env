# Flush

https://www.baldengineer.com/when-do-you-use-the-arduinos-to-use-serial-flush.html

# Slow TCP

https://github.com/esp8266/Arduino/issues/1853
https://stackoverflow.com/questions/45031974/faster-communication-between-two-esp8266-in-client-server-setup

# Garbage Text

https://www.edaboard.com/showthread.php?343985-ESP8266-Weird-Response-to-AT-Commands&s=c9568ebd0d4de7c245813a2d5d11dc75&p=1468266&viewfull=1#post1468266

https://github.com/esp8266/Arduino/issues/4005
    74880
https://arduino.stackexchange.com/a/45630

AT+UART_DEF=9600,8,1,0,0
AT+CIOBAUD=9600!
AT+IPR=9600

See: version of ESP8266 in the board manager

# List Access Points

AT+CWMODE=1
AT+CWLAP

# Tools

http://freeware.the-meiers.org/CoolTermWin.zip
    baudrates.ini

# AT+GMR

Ready
AT+GMR
AT version:1.3.0.0(Jul 14 2016 18:54:01)
SDK version:2.0.0(5a875ba)
Farylink Technology Co., Ltd. v1.0.0.2
May 11 2017 22:23:58
OK
