@ECHO OFF

rem TODO:
rem https://stackoverflow.com/questions/9307512/create-a-batch-file-with-multiple-options

set if=""
for /f %%n in ('wmic nic where "NetConnectionStatus=2 and PhysicalAdapter=true" get NetConnectionID ^| findstr /v /i "vmware virtualbox netconnectionid"') do (
    call :sub %%n
)
echo %if%
exit /b

:sub id
if [%1] == [] goto continue
set if=%1
:continue 
rem
exit /b
