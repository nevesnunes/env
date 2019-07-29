# Debug, Verbose
Set-PSDebug -Trace 2

# Error on uninitialized variables
Set-PSDebug -Strict

# Trace
# Reference: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/trace-command?view=powershell-6
# Input for `-Name`: Get-TraceSource
Trace-Command –Name * -PSHost –Expression {dir} -FilePath out.txt

# List aliases
gci "$((Get-PSProvider Alias | select -ExpandProperty drives).name):"

# +

Compare-Object -SyncWindow 0
Invoke-WebRequest -UseBasicParsing
# ... | Format-Table -AutoSize
