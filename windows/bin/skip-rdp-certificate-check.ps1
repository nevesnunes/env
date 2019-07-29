$array = @("HKCU", "HKLM")
foreach ($i in $array) {
    # Enable remote connections
    reg add "$i\SYSTEM\CurrentControlSet\Control\Terminal Server" /f /v fDenyTSConnections /t REG_DWORD /d 0

    # Skip RDP certificate check
    reg add "$i\SOFTWARE\Microsoft\Terminal Server Client" /f /v AuthenticationLevelOverride /t REG_SZ /d 0
    reg add "$i\SYSTEM\CurrentControlSet\Control\LSA\CredSSP" /f /v UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors /t REG_DWORD /d 0

    # Heartbeat
    #reg add "$i\SYSTEM\CurrentControlSet\Control\Terminal Server" /f /v KeepAliveEnable /t REG_DWORD /d 0
    #reg add "$i\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /f /v TcpMaxDataRetransmissions /t REG_DWORD /d 16
}
