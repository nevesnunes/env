# +
# - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod
Compare-Object -SyncWindow 0
Invoke-WebRequest -UseBasicParsing
... | Format-Table -AutoSize

# References
# - https://4sysops.com/
# - https://aka.ms/pskoans

# WinForms
# - https://4sysops.com/archives/how-to-create-an-open-file-folder-dialog-box-with-powershell/
#     - dialog
# - https://theitbros.com/powershell-gui-for-scripts/
#     - combobox, button
# - https://maikthulhu.github.io/2018-07-14-powershell-forms-controls/
#     - class
# - https://adamtheautomator.com/build-powershell-gui/
#     - designed in visualstudio, imported via xaml
#     - textbox
# - https://poshgui.com/
#     - web designer

# Debug, Verbose
Set-PSDebug -Trace 2

# Error on uninitialized variables
Set-PSDebug -Strict

# Exit on error
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
# Validation:
$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
& {
    $ErrorActionPreference = 'Continue'
    $PSDefaultParameterValues['*:ErrorAction'] = 'Continue'
    foreach ($i in @('lsasdf','ls')) { iex $i }
    # Expect: error + `ls` execution
}
foreach ($i in @('lsasdf','ls')) { iex $i }
# Expect: error
foreach ($i in @('lsasdf','ls')) { iex $i }
# Expect: NOTHING

# Trace
# Reference: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/trace-command?view=powershell-6
# Input for `-Name`: Get-TraceSource
Trace-Command -Name * -PSHost -Expression {Get-ChildItem} -FilePath out.txt

# Script execution
# Reference: https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/
Set-ExecutionPolicy Unrestricted -Force
Get-Content .\foo.ps1 | Invoke-Expression
powershell.exe -noprofile -executionpolicy bypass -file .\foo.ps1

# List aliases
Get-ChildItem "$((Get-PSProvider Alias | select -ExpandProperty drives).name):"

# Test connection
(Invoke-WebRequest -UseBasicParsing -Uri "http://foo:8080").StatusCode -eq 200
Test-NetConnection -ComputerName foo -Port 8080 -InformationLevel "Detailed"
Test-NetConnection -ComputerName foo -DiagnoseRouting -InformationLevel "Detailed"

# Download file
$ProgressPreference = 'SilentlyContinue'
ForEach ($url in @( `
    "https://dl.google.com/tag/s/dl/chrome/install/googlechromestandaloneenterprise64.msi", `
    "https://download.microsoft.com/download/2/d/6/2d61c766-107b-409d-8fba-c39e61ca08e8/vcredist_x64.exe" `
    )) {
    $request = [System.Net.WebRequest]::Create($url)
    $request.AllowAutoRedirect=$true
    $response=$request.GetResponse()
    If ($response.StatusCode -eq "Found") {
        $FileName = [System.IO.Path]::GetFileName((Get-RedirectedUrl $response.GetResponseHeader("Location")))
        Invoke-WebRequest -UseBasicParsing -Uri "$url" -OutFile "$FileName"
    }
}

# Async, Parallel
# https://serverfault.com/questions/626711/how-do-i-run-my-powershell-scripts-in-parallel-without-using-jobs/626712#626712
# https://adamtheautomator.com/powershell-multithreading/
# https://devblogs.microsoft.com/scripting/beginning-use-of-powershell-runspaces-part-1/
$ProgressPreference = 'SilentlyContinue'
$Runspace = [runspacefactory]::CreateRunspacePool(1,8)
$Runspace.Open()
$ps = [powershell]::Create()
$ps.RunspacePool = $Runspace
$Uri = "https://dl.google.com/tag/s/dl/chrome/install/googlechromestandaloneenterprise64.msi"
$OutFile = "chrome.msi"
[void]$ps.AddCommand("Invoke-WebRequest").AddParameter("UseBasicParsing",$true).AddParameter("Uri",$Uri).AddParameter("OutFile",$OutFile)
[void]$ps.BeginInvoke()

# Waiting for all:
# - https://stackoverflow.com/questions/56758549/monitor-the-status-of-runspace-pool-from-a-different-runspace-session

# Checking state:
# - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-runspace?view=powershell-6
# - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/debug-runspace?view=powershell-6
# - https://www.tedon.com/blog/archive/2017/04/05/Debug%20a%20powershell%20script%20running%20in%20powershell%20console%20locally%20or%20remote%20after%20it%20has%20started/
# - https://github.com/nightroman/PowerShelf/blob/master/Add-Debugger.ps1
Get-Runspace
$rs = @(Get-Runspace)[1]
if ($rs.Availability -eq 'Available') {
    $rs.Close()
    $rs.Dispose()
}

# Test
$code = {
    param($rsDataSubset)

    (get-date).DateTime
    foreach ($rsData in $rsDataSubset) {
        $rsData.FullName
    }
}

# Backup
gi .\foo | Compress-Archive -DestinationPath $env:USERPROFILE\Downloads\$(hostname)-foo.zip

# Convert
# FIXME: Only adds first page of multi-page tiff
# References: https://www.ryadel.com/en/multipage-tiff-files-asp-net-c-sharp-gdi-alternative/
Out-Printer -ImagePath $dir\1.pg -PrinterName 'Microsoft Print to PDF' -PrintFileName $dir\1.pdf
# ||
# With ImageMagick: given file size = 498k, execution time = 1m44s
cp $dir\1.pg $dir\1.tif
& 'D:\opt\ImageMagick\convert' $dir\1.tif $dir\1.pdf
rm $dir\1.tif

# Scheduling with events:
# - https://devblogs.microsoft.com/scripting/use-asynchronous-event-handling-in-powershell/

# Expect
# - https://stackoverflow.com/questions/56717302/how-to-send-input-to-consolein-readline-from-parent-process
# - https://www.powershellgallery.com/packages/Await/0.8
# - https://blogs.msdn.microsoft.com/sergey_babkins_blog/2016/12/30/expect-in-powershell/

# Clear command history
Clear-History
# ||
Get-PSReadlineOption | Select-String History
Remove-Item $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Remove-Item $env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

# which
(Get-Command foo).Definition

# servers
# - https://docs.microsoft.com/en-us/windows/win32/adsi/active-directory-service-interfaces-adsi
# - https://blogs.msdn.microsoft.com/dsadsi/2012/01/05/searching-the-active-directory-using-powershell/
# ! s/LDAP:/GC:/
([adsi]"WinNT://WORKGROUP").Children
([adsi]"WinNT://$((Get-WmiObject Win32_ComputerSystem).Domain)").Children

# shares
get-WmiObject -class Win32_Share -computer $server -credential (Get-Credential "domain\admin")

# ||
net view $server

foreach ($i in @( `
    "server1", `
    "server2" `
    )) {
    foreach ($j in $(get-WmiObject -ComputerName $i -Class Win32_Share | % {$_.Name} | ? {$_ -notlike "ADMIN$"})) {
        Get-ChildItem -recurse -filter 'foo*' \\$i\$j\ 2>$null
    }
}

# TODO
# - Get-WmiObject : The RPC server is unavailable. (Exception from HRESULT: 0x800706BA)

# debug object
$event.SourceEventArgs.NewEvent.TargetInstance | ConvertTo-Json -Depth 99

. ~\opt\Get-ExecutableType.ps1
(Get-ChildItem -recurse -file -filter '*.exe').FullName | ForEach-Object {
    New-Object psobject -Property @{
        Path = $_
        ExeType = Get-ExecutableType -Path $_
    }
} |
Format-Table -AutoSize

# loop range
10..1000 | Where-Object { $_ % 5 -eq 0 } | Set-Content 'sequence.txt'

# concurrency
$done = $false
while(-not $done) {
    try {
        $line | out-file $path -append -ea Stop
    }
    catch {
        sleep 1
        continue
    }
    $done = $true
}

# ||
$mutex = new-object System.Threading.Mutex $false,'SomeUniqueName'
nr = $WorkflowData['_Number']
$mutex.WaitOne() > $null
$nr >> C:\nrFile.txt
$mutex.ReleaseMutex()

# ||
# https://www.intertech.com/Blog/avoiding-file-concurrency-using-system-io-filesystemwatcher/

# delete old
Get-ChildItem -Recurse -File | ? {
    [DateTime]$_.LastWriteTime -lt (Get-Date).AddDays(-2)
} | Remove-Item -Force

# delete named
Get-ChildItem -Recurse -File | ? {
    $_.Name -match '^trace'
} | Remove-Item -Force

# find in time range
$today = (Get-Date)
$startDate = $today.Date.AddDays(-14)
$endDate = $startDate.AddDays(7)
Get-ChildItem -Recurse -Path '*/logs/*' | sort lastwritetime | Where-Object {
    [DateTime]$_.Timestamp -ge $startDate -and `
    [DateTime]$_.Timestamp -lt $endDate
}

# ||
Get-ChildItem | sort LastWriteTime | Where-Object {
    [DateTime]$_.LastWriteTime -ge (get-date).AddMinutes(-5) -and `
    [DateTime]$_.LastWriteTime -lt (get-date)
}

# ||
Get-ChildItem | % { get-content $_ -TotalCount 1 2>&1 >$null; $_ } | sort lastwritetime

# ||
# [!] without date, count from tail
$start = -5
$now = get-date
$a = ''
$start..0 | % {
    if ($a) {
        $a += '|'
    }
    $a += '(' + `
        '\s+([0-9]+|' + `
        ($now).AddMinutes($_).ToString('dd.MM.yy') + `
        ')\s+' + `
        ($now).AddMinutes($_).ToString('HH:mm:..') + `
        ')'
}
# Flush items with pending file operations
Get-ChildItem -recurse | ? {
    ! $_.PSIsContainer
} | % {
    get-content $_ -Tail 0 2>$null
}
# Get items with updated file attributes
Get-ChildItem -recurse | ? {
    ! $_.PSIsContainer -and
        [DateTime]$_.LastWriteTime -ge $now.AddMinutes($start) -and
        [DateTime]$_.LastWriteTime -lt $now
} | select-string -CaseSensitive "^ERR.*($a)" | % {
    $raw = $_ | Out-String
    $fields = $raw -Split '([0-9\.]+\s+[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{3})'
    New-Object -TypeName PSCustomObject -Property @{
        Raw = $raw.Trim()
        #Source = $fields[0].Trim()
        Timestamp = $fields[1].Trim()
        #Content = ($fields[2..-1] | % { $_.Trim() }) -Join ' '
    }
} | sort Timestamp | % { $_.Raw }
#} | sort Timestamp | Format-Table -AutoSize -Property Source,Timestamp,Content

# `sort LastWriteTime`: Does not update instantly
# - https://docs.microsoft.com/en-us/dotnet/api/system.io.file.getlastwritetime?view=netframework-4.7.2
# Alternative: Use `System.IO.FileSystemWatcher`
# Alternative:
$files = @()
Get-ChildItem | ? { `
    [DateTime]$_.LastWriteTime -ge (get-date).AddHours(-12) -and `
    [DateTime]$_.LastWriteTime -lt (get-date) `
} | % { `
    $files += ($_.FullName) `
}
Workflow HotTail {
    Param([string[]] $files)
    $ProgressPreference = 'SilentlyContinue'
    foreach -parallel ($file in $files) {
        Get-Content -Path $file -Tail 1 -Wait
    }
}
HotTail $files
# | Tee-Object -FilePath "C:\Temp\foo.log"

# grep
Get-ChildItem -recurse | select-string -pattern 'foo'
Get-ChildItem -recurse -filter '*foo*' | select-object { $_.FullName }
Get-ChildItem -recurse | where-object { $_ | select-string -pattern 'foo' } | select-object { $_.FullName }

# handles
# https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Get-Handles.ps1

# Force file system flush of write operations
Get-ChildItem | ? { ! $_.PSIsContainer } | % { get-content $_ -tail 0 }
Get-ChildItem | ? { ! $_.PSIsContainer } | % { get-content $_ -tail 0; $_ } | sort LastWriteTime

# search all logs
$search = 'hrome'
Get-WinEvent -ListLog * |
    ? { $_.RecordCount -gt 0 } |
    % { Get-WinEvent -FilterHashtable @{StartTime=((Get-Date).AddDays(-1)); LogName=$_.logname} -ea 0 } |
    where message -match $search 2>$null
# ||
$search = 'hrome'
Get-WinEvent -ListLog * |
    ? { $_.RecordCount -gt 0 } |
    % { (Get-EventLog -LogName $_.logname -after (Get-Date).AddDays(-1) | 
        Select-Object -Property Category,Index,TimeGenerated,
        EntryType,Source,InstanceID,Message 2>$nul) -match $search | Format-Table -AutoSize } 2>$null

# rbash
# - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/debug-runspace?view=powershell-6
# - http://technet.microsoft.com/en-us/library/dd347706.aspx

# debug, breakpoints
# - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-pscallstack?view=powershell-6
Set-PSBreakpoint -Command my-alias
Set-PSBreakpoint -Script "sample.ps1" -Variable "Server" -Mode ReadWrite

# xxd
# - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/format-hex?view=powershell-6

# list .NET linked libraries
[system.reflection.assembly]::ReflectionOnlyLoadFrom("$PWD\foo.exe").GetReferencedAssemblies()

# Run with another version compatibility
Powershell.exe -Version 2
# Relaunch script with a given version
if ($PSVersionTable.PSVersion -gt [Version]"2.0") {
   powershell -Version 2 -File $MyInvocation.MyCommand.Definition
   exit
}
# Validation:
$PSVersionTable.PSVersion.Major -eq 2

# output to clipboard
$OutputEncoding = New-Object System.Text.UnicodeEncoding($false, $false)
"foo" | clip

# diff recursive
# Alternative: fc.exe
&{
    $Folder1=""
    $Folder2=""
    Compare-Object `
        (Get-ChildItem -recurse "$Folder1") `
        (Get-ChildItem -recurse "$Folder2") `
        -Property Name, Length | ? {
            $_.SideIndicator -eq "<="
    } | % {
        $Name = $_.Name
        Write-Output $Name "---"
        Compare-Object `
            (Get-Content "$Folder1\$Name" | ? {$_.trim() -ne "" }) `
            (Get-Content "$Folder2\$Name" | ? {$_.trim() -ne "" }) |
        Format-Table -AutoSize SideIndicator,InputObject
    }
}

# ast
[System.Management.Automation.Language.Parser]::ParseInput(
    '$()',
    [ref]$null,
    [ref]$null
).FindAll({$true}, $true) | % {
    $_.GetType().FullName,$_ | Format-List
}

# ||
foo | Get-Member

# ||
foo | Select-Object -Property *

# - https://vexx32.github.io/2018/12/20/Searching-PowerShell-Abstract-Syntax-Tree/
# - https://jamieo.com/2019/05/10/managing-complex-powershell-applications/
# - https://ss64.com/ps/syntax-operators.html
# - https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.language.scriptblockast?view=pscore-6.2.0

# enumerate com objects / types
Get-ChildItem HKLM:\Software\Classes -ErrorAction SilentlyContinue | Where-Object {
   $_.PSChildName -match '^\w+\.\w+$' -and (Test-Path -Path "$($_.PSPath)\CLSID")
} | Select-Object -ExpandProperty PSChildName

# testing
# - https://github.com/pester/Pester
# - https://stackoverflow.com/questions/43213624/how-can-i-automatically-syntax-check-a-powershell-script-file

# workaround commands supporting limited character set
$encoded_name = [Web.HttpUtility]::UrlEncode("utf8_name")
cmd /c mklink $supported_name $encoded_name
Rename-Item $encoded_name [Web.HttpUtility]::UrlDecode($encoded_name)

# remote
Invoke-Command -ComputerName localhost -ScriptBlock {
    foo
}

# copy recursive creating root folder
Copy-Item C:\Foo1 -Destination C:\Foo2 -Recurse

# copy recursive skipping root folder
Get-ChildItem C:\Foo1 | Copy-Item -Destination C:\Foo2 -Recurse

# copy long paths
Copy-Item -LiteralPath '\\?\C:\folder\subfolder' -Destination 'D:\folder'

# copy only new files
$exclude = Get-ChildItem -recurse $Destination
Copy-Item -Recurse $Source $Destination -Exclude $exclude

# escaping
$escaped = [Regex]::Escape("\\server\foo")
$unescaped = ConvertFrom-StringData -stringdata $escaped

# space usage
(Get-ChildItem -Recurse).Length | measure -Sum

# space usage per child
Get-ChildItem -Dir -Recurse | %{
    New-Object -TypeName PSCustomObject -Property @{
        Name = $_.FullName
        Size = ((gci -File $_.FullName | measure Length -Sum).Sum) / 1MB
    }
}

# Initialize environment from parsed batch variables
Set-Variable $_.Groups[1].Value $_.Groups[2].Value
$ExecutionContext.InvokeCommand.ExpandString
[Environment]::SetEnvironmentVariable($_.Groups[1].Value,
   [System.Environment]::SetEnvironmentVariable( `
       $_.Groups[1].Value, `
       [System.Environment]::ExpandEnvironmentVariables(($_.Groups[2].Value -replace '%(.*)%', '$env:$1'))
   Set-Variable $_.Groups[1].Value $_.Groups[2].Value

# ||
Select-String '^\s*@?set ([^=]*)=(.*)' .\foo.bat | % {
    $_.Matches
} | % {
    [System.Environment]::SetEnvironmentVariable( `
        $_.Groups[1].Value, `
        [System.Environment]::ExpandEnvironmentVariables($_.Groups[2].Value))
}

# ISO mounting

# Support older Windows versions:
# - https://gist.github.com/Thermionix/6806471

# TODO: Ensure running as admin:
# - https://serverfault.com/questions/95431/in-a-powershell-script-how-can-i-check-if-im-running-with-administrator-privil/97599

ForEach ($i in @(Get-ChildItem $iso_dir -filter '*.iso')) {
    $mountResult = Mount-DiskImage -StorageType ISO -ImagePath $i.FullName -PassThru
    $driveLetter = ($mountResult | Get-Volume).DriveLetter
    Get-Content ${driveLetter}:\foo
    Get-DiskImage $i.FullName | Dismount-DiskImage
    # Alternative:
    # Get-Volume $driveLetter | Get-DiskImage | Dismount-DiskImage
}

# execution time
# - https://stackoverflow.com/questions/3513650/timing-a-commands-execution-in-powershell
Measure-Command {
    foo | Out-Default
}

# ||
Get-History -Count 1 | % { $_.EndExecutionTime - $_.StartExecutionTime }

# magic bytes
(get-content DATA -raw -encoding Byte)[0..4] | format-hex | select-string pdf
[System.BitConverter]::ToString((get-content DATA -raw -encoding Byte)[0..4]) | select-string '25-50-44-46'

# change language
$culture = [System.Globalization.CultureInfo]::CreateSpecificCulture("en-US")
$assembly = [System.Reflection.Assembly]::Load("System.Management.Automation")
$type = $assembly.GetType("Microsoft.PowerShell.NativeCultureResolver")
$field = $type.GetField("m_uiCulture", [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static)
$field.SetValue($null, $culture)

# normalize string
'asdf;./Aãõ^a'.Normalize("FormD") -replace '\p{M}' -replace '\W','_'

# release memory
$app.quit()
# release the memory immediately
$app = $null
# call garbage collection
[gc]::collect()
[gc]::WaitForPendingFinalizers()

# long path / extended-length path / UNC path
# https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file
ls C:\Users\foo
ls \\?\C:\Users\foo\*
ls \\localhost\C$\Users\foo
ls \\?\UNC\localhost\C$\Users\foo\*

# list processes
Get-CimInstance -Class Win32_Process | Format-Table -Property ProcessId, ProcessName, CommandLine -Autosize

# killall
Get-Process | Where-Object {$_.ProcessName -like "winword"} | Stop-Process -Force

# open in editor
# https://github.com/zyedidia/micro
start "" powershell_ise foo

# run command in another interface language
# ||
# https://stackoverflow.com/questions/4105224/how-to-set-culture-in-powershell
[Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'; ./foo

# Scheduled Tasks
# - https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtask?view=win10-ps

### Create

$action = New-ScheduledTaskAction `
    -Execute 'cmd.exe' `
    -Argument '/c "\\foo\d$\bar\baz_minimized.bat"'
### || without window
$action = New-ScheduledTaskAction `
    -Execute 'wscript.exe' `
    -Argument '/b /NoLogo "\\foo\d$\bar\baz.vbs"'

$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5) `
    -RepetitionDuration (New-TimeSpan -Days (365 * 50))
$principal = New-ScheduledTaskPrincipal `
    -GroupId "BUILTIN\Administrators" `
    -RunLevel Highest
Register-ScheduledTask `
    -Action $action `
    -Principal $principal `
    -Trigger $trigger `
    -TaskName "baz" `
    -Description "Process baz"

### Validation

schtasks /v /tn baz /fo list

### Delete

Unregister-ScheduledTask `
    -TaskName "baz" `
    -Confirm:$false

### baz_minimized.bat
###
### start /min D:\bar\baz.bat
###
### baz.vbs
###
### Dim WinScriptHost
### Set WinScriptHost = CreateObject("WScript.Shell")
### WinScriptHost.Run Chr(34) & "D:\bar\baz.bat" & Chr(34), 0
### Set WinScriptHost = Nothing

# importing dlls
# - https://www.leeholmes.com/blog/2006/10/27/load-a-custom-dll-from-powershell/
# - https://stackoverflow.com/questions/7972141/run-my-third-party-dll-file-with-powershell
# - https://stackoverflow.com/questions/16926127/powershell-to-resolve-junction-target-path

# process lines of strings
[regex]::split(@'
1
2
3
'@.trim(), '[\r\n]+') | % { $_ }

# cpu architecture
if ([System.IntPtr]::Size -eq 8) { echo 64 } else { echo 32 }

# active directory user lookup
dsquery user -name foo
gpresult /r
whoami /fqdn

# list links
fsutil hardlink list .
fsutil hardlink list "C:\Documents and Settings\All Users\Application Data\Microsoft\Crypto"
# C:\ProgramData\Microsoft\Crypto
gci -recurse -force | ?{$_.LinkType} | select FullName,LinkType,Target

# group by repeated elements
choco list -localonly -all |
ForEach-Object {
    $fields = $_ -Split ' +'
    New-Object -TypeName PSCustomObject -Property @{
        Name = $fields[0].Trim()
        Version = ($fields[1..($fields.length - 1)] | ForEach-Object { $_.Trim() }) -Join ' '
    }
} |
Group-Object -Property Name |
Where-Object {
    $_.Count -gt 1
} |
Sort-Object -Property Count

# Count Name                      Group
# ----- ----                      -----
#     2 chocolatey-core.extension {@{Version=1.3.5.1; Name=chocolatey-core.extension}, @{Version=1.3.3; Name=chocolatey-c...
#     2 Chocolatey                {@{Version=v0.10.15; Name=Chocolatey}, @{Version=0.10.15; Name=chocolatey}}
#     5                           {@{Version=; Name=}, @{Version=- A pending system reboot request has been detected, how...
#
#
# PS C:\Users\foo\bin> choco uninstall chocolatey-core.extension --version 1.3.3

# mac address (physical adapter)
# Reference: https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-networkadapter
Get-CimInstance -Query "select * from win32_networkadapter where PNPDeviceID like '%PCI%' AND AdapterTypeID='0'" |
Select-Object Description, MACAddress |
Select-String Ethernet

# Convert to base64
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('Motörhead'))

# Convert from base64
[Text.Encoding]::Utf8.GetString([Convert]::FromBase64String('TW90w7ZyaGVhZA=='))

# filter event log
# Reference: https://docs.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable?view=powershell-7
Get-WinEvent -FilterHashtable @{StartTime=((Get-Date).AddHours(-1)); LogName='Application'} | ? { $_.ProviderName -match 'OpenVPN*' }

# Transferring binary content by clipboard
# - https://gist.github.com/ethzero/47f657ca635752b5bdb45f99eae40182
# => base64

# On the transmission end:
$Content = Get-Content -Encoding Byte -Path binaryfile.xxx
[System.Convert]::ToBase64String($Content) | clip

# On the receiving end:
# Paste the Base64 encoded contents in a text file manually:
$Base64 = Get-Content -Path binaryfile.xxx.base64_encoded.txt
Set-Content -Value $([System.Convert]::FromBase64String($Base64)) -Encoding Byte -Path binaryfile.zip

# https://ss64.com/ps/syntax-base36.html
# => base36

function ConvertTo-Base36 {
    [CmdletBinding()]
    param ([parameter(valuefrompipeline=$true, HelpMessage="Integer number to convert")][int]$decNum="")
    $alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    do {
        $remainder = ($decNum % 36)
        $char = $alphabet.substring($remainder,1)
        $base36Num = "$char$base36Num"
        $decNum = ($decNum - $remainder) / 36
    }
    while ($decNum -gt 0)

    $base36Num
}
function ConvertFrom-Base36 {
    [CmdletBinding()]
    param ([parameter(valuefrompipeline=$true, HelpMessage="Alphadecimal string to convert")][string]$base36Num="")
    $alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    $inputarray = $base36Num.tolower().tochararray()
    [array]::reverse($inputarray)
    [long]$decNum=0
    $pos=0

    foreach ($c in $inputarray) {
        $decNum += $alphabet.IndexOf($c) * [long][Math]::Pow(36, $pos)
        $pos++
    }
    $decNum
}

# execution alternatives
# - https://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/
# - https://github.com/palantir/alerting-detection-strategy-framework/blob/master/ADS-Examples/004-Unusual-Powershell-Host-Process.md
# - https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe/
# - https://cobbr.io/InsecurePowershell-PowerShell-Without-System-Management-Automation.html

# search string with context, grep -A 5 -B 5 equivalent
Select-String 'foo' -Context 5

# tail -n 5 equivalent
foo | Select-Object -Last 5

# remote command
Invoke-Command -ComputerName foo -ScriptBlock { foo }

# hidden items
(Get-Item -Force -LiteralPath C:\ProgramData).Attributes
# ||
Get-ChildItem C:\ -Recurse -Force | Where { ($_.Attributes.ToString() -Split ", ") -Contains "Hidden" } | Select-Object -ExpandProperty FullName

# event started
(Get-EventLog -LogName "System" -Source "Service Control Manager" -EntryType "Information" -Message "*Print Spooler service*running*" -Newest 1).TimeGenerated

# test file exists
if ([System.IO.File]::Exists($AbsoluteFilePath)) {
    # ...
}

# run as nt authority\system
powershell -ep bypass "Install-Module -Name NtObjectManager; $v = start-Win32ChildProcess cmd"

# current running processes cmdline
Get-WmiObject Win32_Process | Select-Object Name,CommandLine

# pager
foo | out-host -paging
# Search = Context Menu > Edit > Find...
# ||
more
# ||
foo | sls 'FATAL|ERROR|WARN'
# ||
# match in time range

# system info
Get-ComputerInfo
# ||
Get-WmiObject Win32_ComputerSystem
Get-WmiObject Win32_OperatingSystem
Get-WmiObject Win32_BIOS
Get-WmiObject Win32_Processor
Get-WmiObject Win32_LogicalDisk

# Memory Usage
Get-Process -Name foo | %{$_.PM} | Measure-Object -Sum

# man
# - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-help?view=powershell-7
Update-Help
Get-Help Format-Table -Full

# balloon notifications
# - System.Windows.Forms.NotifyIcon
#     - https://www.powershellgallery.com/packages/BurntToast/0.6.2
msg.exe 5 /server:server1 This is a message to the user in Session 5 on server 1

# remove registry item
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Remove-ItemProperty -Name 'Foo Service' Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

# wait for network
do { sleep 5 } until(Test-NetConnection | ? { $_.PingSucceeded })
# ||
do { sleep 5 } until(Test-NetConnection $HOST -Port $PORT | ? { $_.TcpTestSucceeded })
