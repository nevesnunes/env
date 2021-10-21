# tools

- P32Dasm
- VB Decompiler Pro
- Numega SmartCheck
- [VBReFormer](https://qiil.io/VBReFormer.aspx)

- VB native code: OllyDbg, IDA
- VB P-code: WKTVBDE, VB Decompiler Pro

# bootstrap

- https://docs.microsoft.com/en-us/previous-versions/visualstudio/visual-basic-6/visual-basic-6-support-policy?redirectedfrom=MSDN
- https://social.technet.microsoft.com/Forums/en-US/a28f7dc4-2c43-4bcb-946e-f620290d3d82/vb6-installation-on-windows-10-64-bit-os?forum=win10itprogeneral
- http://blog.danbrust.net/2015/09/14/installing-visual-basic-studio-6-on-windows-10

> Component 'mswinsck.ocx' or one of its dependencies not correctly registered: a file is missing or invalid

```
regsvr32 %Systemroot%\SysWOW64\Comdlg32.ocx
regsvr32 /u %Systemroot%\SysWOW64\Comdlg32.ocx
regsvr32 /i %Systemroot%\SysWOW64\Comdlg32.ocx
# ||
regsvr32 %Systemroot%\System32\Comdlg32.ocx
regsvr32 /u %Systemroot%\System32\Comdlg32.ocx
regsvr32 /i %Systemroot%\System32\Comdlg32.ocx
```

> The module ".\Ocx\COMDLG32.ocx" may not be compatible with the version of Windows that you're running. Check if the module is compatible with an x86 (32-bit) or x64 (64-bit) version of regsvr32.exe.

> ".\Ocx\COMDLG32.ocx" is not an executable file and no registration helper is registered for this file type.

- https://www.program-transformation.org/Transform/VisualBasicDecompilers
- https://gist.github.com/williballenthin/dcbafede053a5a51d99c581acf846e1b
- http://web.archive.org/web/20101127044116/http://vb-decompiler.com/pcode/opcodes.php?t=1
- http://sandsprite.com/CodeStuff/debug_p_code.html

# examples

- [SECCON 2016 CTF の Retrospective \- Qiita](https://qiita.com/masahiro_sakai/items/7258ef1f9e98373de36f)
- https://github.com/Inndy/ctf-writeup/tree/master/2016-seccon/retrospective

```bash
winetricks comctl32ocx
winetricks comdlg32ocx
winetricks richtx32
winetricks vb6run
```

- http://www.belgeci.com/an-interesting-tool-numega-smartcheck-5-0.html

```
CALL USER!GETWINDOWTEXT >> Get what you typed
LEA AX,[BP-32] >> Load AX with address of what you typed
PUSH SS >> Segment of what you typed
PUSH AX >> Offset of what you typed
PUSH DS >> Segment of real password
PUSH 06BA >> Offset of real password
CALL USER!LSTRCMP >>Comparison of strings at ss:ax and ds:09d6

Next you do a dump of 06ba:
d ds:06ba l 64

You should see the password

ADD ESP,04
LEA EAX,[EBP-14] >> Your password
LEA ECX,[EBP-28] >> The correct password
PUSH EAX >> Your password
PUSH ECX >> The correct password
CALL 10005680
```
