; Autorun - Press X
#IfWinActive, ahk_class LaunchUnrealUWindowsClient
~*x::
If GetKeyState("w")
Send {shift up}{w Up}
Else
Send {shift down}{w Down}
Return
#IfWinActive
