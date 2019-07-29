; Recommended for performance and compatibility with future AutoHotkey releases
#NoEnv 

; Keeps a script permanently running
#Persistent 

; Enable warnings to assist with detecting common errors
#Warn 

; Ensures a consistent starting directory
SetWorkingDir %A_ScriptDir% 

; Improve script speed and reliability
Process, Priority,, High 
SendMode Input 
SetBatchLines, -1 

;;; Window Messages

Gui +LastFound 
hWnd := WinExist() 

DllCall( "RegisterShellHookWindow", UInt,hWnd ) 
MsgNum := DllCall( "RegisterWindowMessage", Str,"SHELLHOOK" ) 
OnMessage( MsgNum, "ShellMessage" ) 
Return 

MoveAfterTitleChange(title, lParam) {
    WinGetTitle, _title, ahk_id %lParam%
    if (_title != title)
        MoveWithDefaults(lParam, True)
    return
}

MoveWithDefaults(lParam, isTitleStable) {
    SetTitleMatchMode,RegEx

    ; Skip modal dialog windows
    WinGet, _style, ExStyle, ahk_id %lParam%
    if (_style & 0x8)
        return

    WinGet, _name, ProcessName, ahk_id %lParam%
    WinGetClass, _class, ahk_id %lParam%
    WinGetTitle, _title, ahk_id %lParam%

    if RegExMatch(_name, "("
           . "Wireshark.+"
           . ")") > 0
       WinMaximize, ahk_id %lParam%
    else if RegExMatch(_name, "i)("
           . "powershell.+"
           . ")") > 0
       MoveInCurrentMonitorWithID(0, 0, -1, -1, lParam)
    else if RegExMatch(_name, "i)("
           . "Telegram.exe|vimrun.exe"
           . ")") > 0
       MoveInLargestMonitorWithID(1.85, 0, 0.35, 1, lParam)
    else if RegExMatch(_title, "("
           . "Google Hangouts|Hangouts Video Call|Katalon Recorder|Selenium IDE( - .*)?$"
           . ")") > 0
       MoveInLargestMonitorWithID(1.85, 0, 0.35, 1, lParam)
    else if RegExMatch(_class, "("
           . "ExploreWClass|CabinetWClass|"
           . "TaskManagerWindow|"
           . "Vim"
           . ")") > 0
       MoveInLargestMonitorWithID(1.85, 0, 0.35, 1, lParam)
    else if RegExMatch(_title, "("
           . "SQL Workbench"
           . ")") > 0
       MoveInLargestMonitorWithID(0, 0, 0.65, 1, lParam)
    else if RegExMatch(_name, "("
           . "SumatraPDF.exe"
           . ")") > 0
       MoveInLargestMonitorWithID(0, 0, 0.65, 1, lParam)
    else if RegExMatch(_class, "("
           . "mintty|VirtualConsoleClass"
           . ")") > 0
       MoveInLargestMonitorWithID(0, 0, 0.65, 1, lParam)
    else if RegExMatch(_class, "("
           . "Chrome.+"
           . ")") > 0 and isTitleStable
       MoveInLargestMonitorWithID(0, 0, 0.65, 1, lParam)
}

ShellMessage(wParam, lParam) {
    ; HSHELL_WINDOWCREATED := 1
    If ( wParam = 1 ) {
        WinGetTitle, _title, ahk_id %lParam%

        MoveWithDefaults(lParam, False)

        ; Window may change title after creation
        func := Func("MoveAfterTitleChange").Bind(_title, lParam)
        SetTimer, % func, -500
    }
}

#,::
    WinGet,Windows,List
    Loop,%Windows%
    {
        _id := Windows%A_Index%
        MoveWithDefaults(_id, True)
    }
Return

;;; Run or Activate

Activate(class) {
    winActiveID := WinExist("A")

    ; Workaround focus issues
    ; WinActivate, Program Manager

    WinGet, Instances, List, ahk_class %class%
    Loop, %Instances% {
        winInstanceID := Instances%A_Index%
        if (winInstanceID != winActiveID) {
            WinActivate, ahk_id %winInstanceID%
            return
        }
    }
}

ActivateExcludingTitle(class, title) {
    winActiveID := WinExist("A")
    WinGet, WindowList, List, ahk_class %class%
    Loop %WindowList% { 
        winInstanceID := WindowList%A_Index% 
        WinGetTitle, WinTitle, ahk_id %winInstanceID% 
        If RegExMatch(WinTitle, title) == 0 {
            if (winInstanceID != winActiveID) {
                WinActivate, ahk_id %winInstanceID%
                return
            }
        }
    }
}

#Enter::
    SetTitleMatchMode,RegEx
    class = (mintty|VirtualConsoleClass)
    IfWinNotExist, ahk_class %class%
        Run, ConEmu64
    Else
        Activate(class)
Return

#+b:: Run, chrome
#b::
    SetTitleMatchMode,RegEx
    class = Chrome.+
    IfWinNotExist, ahk_class %class%
        Run, chrome
    Else
        ActivateExcludingTitle(class, "("
           . "Google Hangouts|Hangouts Video Call|Katalon Recorder|Selenium IDE( - .*)?$"
           . ")")
Return

#+f:: Run, explorer
#f::
    SetTitleMatchMode,RegEx
    class = (Explore|Cabinet)WClass
    IfWinNotExist, ahk_class %class%
        Run, explorer
    Else
        Activate(class)
Return

#+v:: Run, gvim
#v::
    class = Vim
    IfWinNotExist, ahk_class %class%
        Run, gvim
    Else
        Activate(class)
Return

;;; Window Management

Move(_x, _y, _w, _h, _id, _mid) {
    SysGet, Mon, MonitorWorkArea, %_mid%

    monitorWidth := Abs(MonRight - MonLeft)
    if (monitorWidth < 1400) {
      if (_x == 1.85) {
          _x = 1.00
      }
      if (_w == 0.65 || _w == 0.35) {
          _w = 0.50
      }
    }

    WinGetPos,X,Y,W,H,ahk_id %_id%,,,
    WinGet,M,,ahk_id %_id%
    NewW := (MonRight - MonLeft) * _w
    if (_w == -1)
        NewW := W
    NewH := (MonBottom - MonTop) * _h
    if (_h == -1)
        NewH := H
    NewX := MonLeft + (NewW * _x)
    if (_x == -1)
        NewX := X
    NewY := MonTop + (NewH * _y)
    if (_y == -1)
        NewY := Y

    if( M != 0 )
        WinRestore,ahk_id %_id%
    WinMove,ahk_id %_id%,,NewX,NewY,NewW,NewH
    return
}

MoveInCurrentMonitorWithID(_x, _y, _w, _h, _id) {
    ; Calculate the top center edge
    WinGetPos,X,Y,W,H,ahk_id %_id%,,,
    CX := X + W/2
    CY := Y + 20

    SysGet, Count, MonitorCount
    num = 1
    Loop, %Count% {
        SysGet, Mon, MonitorWorkArea, %num%
        if (CX >= MonLeft && CX <= MonRight && CY >= MonTop && CY <= MonBottom) {
            Move(_x, _y, _w, _h, _id, num)
            return
        }
        num += 1
    }
    return
}
MoveInCurrentMonitor(_x, _y, _w, _h) {
    WinGet,_wid,ID,A
    MoveInCurrentMonitorWithID(_x, _y, _w, _h, _wid) 
    return
}

MoveInLargestMonitorWithID(_x, _y, _w, _h, _id) {
    SysGet, Count, MonitorCount
    num = 1
    largestWidth = 0
    targetMonitor = 1
    Loop, %Count% {
        SysGet, Mon, MonitorWorkArea, %num%
        currentWidth := Abs(MonRight - MonLeft)
        if (currentWidth >= largestWidth) {
            largestWidth = %currentWidth%
            targetMonitor = %num%
        }
        num += 1
    }

    Move(_x, _y, _w, _h, _id, targetMonitor)
    return
}
MoveInLargestMonitor(_x, _y, _w, _h) {
    WinGet,_wid,ID,A
    MoveInLargestMonitorWithID(_x, _y, _w, _h, _wid) 
    return
}

#+h:: MoveInCurrentMonitor(0, 0, 0.50, 1)
#+l:: MoveInCurrentMonitor(1.00, 0, 0.50, 1)

#^h::
#!h:: MoveInCurrentMonitor(0, 0, 0.65, 1)

#^l::
#!l:: MoveInCurrentMonitor(1.85, 0, 0.35, 1)

#^u::
#!u:: MoveInCurrentMonitor(0, 0, 0.65, 0.50)

#^n::
#!n:: MoveInCurrentMonitor(0, 1, 0.65, 0.50)

#^i::
#!i:: MoveInCurrentMonitor(1.85, 0, 0.35, 0.50)

#^m::
#!m:: MoveInCurrentMonitor(1.85, 1, 0.35, 0.50)

#^k::
#!k:: MoveInCurrentMonitor(0, 0, 1, 0.50)

#^j::
#!j:: MoveInCurrentMonitor(0, 1, 1, 0.50)

#+j:: WinMinimize, A
#+k::
    WinGet, MX, MinMax, A
    If MX
        WinRestore, A
    Else
        WinMaximize, A
Return

#^w:: Winset, Alwaysontop, TOGGLE, A

;;; +

#.:: DllCall("SetCursorPos", int, 9999, int, 9999)

#^p:: SendRaw %clipboard%

<^>!f:: Send {esc}
XButton1:: Send {MButton}
XButton2:: Send {MButton}

; TODO: ocr screenshot
; run, %userprofile%\opt\msys64\usr\bin\bash.exe -l -c 'exec ocr.sh' > out
