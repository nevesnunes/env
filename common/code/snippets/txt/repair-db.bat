Sc config wsearch start=disabled
Net stop WMPNetworkSvc
Net stop wsearch
pause
esentutl.exe /d %AllUsersProfile%\Microsoft\Search\Data\Applications\Windows\Windows.edb
Sc config wsearch start=delayed-auto
Net start wsearch
Net start WMPNetworkSvc
pause
