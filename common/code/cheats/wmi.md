# Extract share users

```ps1
$cred = Get-Credential -Credential iammred\administrator
$share = "data"
$cn = "hyperv1"
$query = "
    Associators of {win32_LogicalShareSecuritySetting='$share'}
    Where resultclass = win32_sid
"
Get-WmiObject -query $query -cn $cn -cred $cred | Select-Object -Property @{
        LABEL="User";
        EXPRESSION={"{0}\{1}" -f $_.ReferencedDomainName, $_.AccountName}
    }, `
    SID

# https://gallery.technet.microsoft.com/scriptcenter/List-Share-Permissions-83f8c419
# https://community.spiceworks.com/topic/1978899-list-all-shared-folders-and-users
[cmdletbinding()]
param([Parameter(ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True)]$Computer = '.')

$shares = gwmi -Class win32_share -ComputerName $computer | select -ExpandProperty Name
foreach ($share in $shares) {
    $acl = $null
    Write-Host $share -ForegroundColor Green
    Write-Host $('-' * $share.Length) -ForegroundColor Green
    $objShareSec = Get-WMIObject -Class Win32_LogicalShareSecuritySetting -Filter "name='$Share'"  -ComputerName $computer
    try {
        $SD = $objShareSec.GetSecurityDescriptor().Descriptor
        foreach($ace in $SD.DACL){
            $UserName = $ace.Trustee.Name
            If ($ace.Trustee.Domain -ne $Null) {$UserName = "$($ace.Trustee.Domain)\$UserName"}
            If ($ace.Trustee.Name -eq $Null) {$UserName = $ace.Trustee.SIDString }
            [Array]$ACL += New-Object Security.AccessControl.FileSystemAccessRule($UserName, $ace.AccessMask, $ace.AceType)
            } #end foreach ACE
    } catch {
        Write-Host "Unable to obtain permissions for $share"
    }
    $ACL
}
```

# Scenarios

https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf
https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/
https://khr0x40sh.wordpress.com/2014/06/10/moftastic_powershell/

# API

https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic
https://docs.microsoft.com/en-us/windows/win32/wmisdk/--instancecreationevent
https://docs.microsoft.com/en-us/dotnet/api/system.io.filesystemwatcher?view=netframework-4.8
https://docs.microsoft.com/en-us/dotnet/api/system.io.filesystemeventargs?view=netframework-4.8

# ETW

https://medium.com/palantir/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63
https://github.com/microsoft/perfview/blob/master/documentation/TraceEvent/TraceEventProgrammersGuide.md

# Bugs

https://stackoverflow.com/questions/1764809/filesystemwatcher-changed-event-is-raised-twice

# +

```ps1
Register-WmiEvent `
    -Query "
    SELECT *
    FROM __InstanceModificationEvent
    WITHIN 5
    WHERE TargetInstance ISA 'CIM_DataFile'
        and TargetInstance.FileSize > 2000000
        and TargetInstance.Path = '\\Users\\lex\\Important'
        and targetInstance.Drive = 'C:'
        and targetInstance.Extension ='xlsx'" `
    -Action $action
```

Log WMI consumers
    https://github.com/realparisi/WMI_Monitor
    https://docs.microsoft.com/en-us/windows/win32/wmisdk/tracing-wmi-activity
    ```
    Get-WMIObject -Namespace root\Subscription -Class __EventFilter
    Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
    Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
    ```

Event fields
    https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-process

eventvwr > Custom Views > Create Custom View... > Event Level: Check all
    ? profiling
~/bin/watchTempFiles.ps1

performance counters via ETW
    http://msdn.microsoft.com/en-us/library/windows/desktop/bb756968.aspx

event logs and publishers
    https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
    ```
    wevtutil /el
    ```
! permanent event consumer
    ```ps1
    # References:
    # http://trevorsullivan.net/2011/01/17/powershell-wmi-eventing-monitor-cpu-speed/
    # Dependencies:
    # https://github.com/pcgeek86/PowerEvents
    $Filter = New-WmiEventFilter `
        -Name CPUClockSpeedChanged `
        -Query @"
            select *
            from __InstanceModificationEvent
            within 2
            where TargetInstance ISA 'Win32_Processor' and
                TargetInstance.CurrentClockSpeed <> PreviousInstance.CurrentClockSpeed
"@
    $Consumer = New-WmiEventConsumer `
        -Name CPUClockSpeedChanged `
        -ConsumerType LogFile `
        -FileName c:tempClockSpeed.log `
        -Text "Clock speed on %TargetInstance.SocketDesignation% changed to: %TargetInstance.CurrentClockSpeed%"
    New-WmiFilterToConsumerBinding -Filter $Filter -Consumer $Consumer
    ```
    https://devblogs.microsoft.com/scripting/use-powershell-to-create-a-permanent-wmi-event-to-launch-a-vbscript/
    https://stackoverflow.com/questions/27107902/permanent-wmi-event-consumer-doesnt-get-triggered-temporary-does
    https://learn-powershell.net/2013/08/14/powershell-and-events-permanent-wmi-event-subscriptions/
    https://www.codeproject.com/Articles/28226/Creating-WMI-Permanent-Event-Subscriptions-Using-M
    https://docs.microsoft.com/en-us/windows/win32/wmisdk/receiving-events-at-all-times?redirectedfrom=MSDN
    https://stackoverflow.com/questions/10139270/process-start-event-using-wmi-not-all-process-starts-being-detected

! cross-reference process name with file system events
    https://stackoverflow.com/questions/38127255/get-created-modified-deleted-files-by-a-specific-process-from-an-event-tracing

https://devblogs.microsoft.com/scripting/use-powershell-to-monitor-specific-process-creation/

! Windows File Auditing
    gpmc.msc > Group Policy Management > Forest "foo" > Domains > "foo" > Default Domain Policy > "Enable Audit Policy"
    gpedit.msc > Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Audit Policy > Audit object access = Enabled
        => event ID 4663
    https://www.varonis.com/blog/windows-file-system-auditing/


