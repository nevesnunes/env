@ECHO OFF

route delete 10.0.0.0
ipconfig /flushdns

set if="Ethernet"
rem netsh interface ipv4 add dnsserver %if% 192.168.69.245 index=1
netsh interface ipv4 delete dnsserver %if% all
set if="Wi-Fi"
rem netsh interface ipv4 add dnsserver %if% 192.168.69.245 index=1
netsh interface ipv4 delete dnsserver %if% all
