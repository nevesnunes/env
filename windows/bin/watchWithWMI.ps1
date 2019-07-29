$query = "SELECT * FROM __InstanceCreationEvent WHERE TargetInstance ISA 'Win32_NTLogEvent' "
Register-WmiEvent -Source Demo1 -Query $query -Action { 
                Write-Host "Log Event occurred" 
                Write-Host "EVENT MESSAGE" 
                Write-Host $event.SourceEventArgs.NewEvent.TargetInstance.Message}