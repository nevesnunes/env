# Control Panel\User Accounts\Credential Manager
# Edit (Remote Desktop Connection)

reg delete "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default" /va /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers"

cd ~\Documents\
attrib Default.rdp -s -h
del Default.rdp

rd -r '~\AppData\Local\Microsoft\Terminal Server Client\Cache'

ipconfig /flushdns
