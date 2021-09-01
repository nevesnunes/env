http://play.inginf.units.it/#/level/1

`\d+`

--------------------------------------
http://play.inginf.units.it/#/level/2

`(\w+)(\:\w+){5}`
`(\w+:){5}\w+`

--------------------------------------
http://play.inginf.units.it/#/level/3

`ftp://ftp\d?\d?\.?\w?\w?\.FreeBSD\.org/pub/FreeBSD/`
`ftp:\S+`

--------------------------------------
http://play.inginf.units.it/#/level/4

`\$.+?\$`

--------------------------------------
http://play.inginf.units.it/#/level/5

`\d+(\.\d+)+`
`(\d+\.){3}\d+`

--------------------------------------
http://play.inginf.units.it/#/level/6

`href=(['"]).+?\1`

--------------------------------------
http://play.inginf.units.it/#/level/7

`http://[\S]+(?:(?=\s|\.|\>))` (Not Working)
`http://[^ >]+[\w/]`

--------------------------------------
http://play.inginf.units.it/#/level/8

`<h(\d)>?.+</h\1>`

--------------------------------------
http://play.inginf.units.it/#/level/9

`\(?\d{3}\)?.\d{3}.\d{4}`
`\(?\d+\)?[ -./]\d+[-.]\d+`

--------------------------------------
http://play.inginf.units.it/#/level/10

`\w+\,\s.+?\w+` (Not Working)
`(?<=[{ ])\w+(-\w+)?,( [A-Z]\w*(({.+?}|')\w+)?)+`

--------------------------------------
http://play.inginf.units.it/#/level/11

`(?<=<h(\d)>).+?(?=</h\1>)` (Not Working)
`(?<=<h(\d).*?>).+(?=</h\1>)`

--------------------------------------
http://play.inginf.units.it/#/level/12

`(?<=\d+\.\s)\w+\,\s[\.\w]+(?=[\,\:])`
`(?<=\. )\w+, (.\.)+`