# +

https://community.osr.com/

# vms

https://developer.microsoft.com/en-us/windows/downloads/virtual-machines

# modify disk partition

diskmgmt.msc
disable virtual memory

# network packet sniffer

fiddler

# debug - crash dump, memory dump

https://docs.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps
https://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-15-WinDbg-Bugchecks

# WMI event handlers

https://technet.microsoft.com/en-us/library/ff898417.aspx

# Verbatim Path Syntax

```
\\?\C:\Temp\COM2.TXT
```

# Browse volume over network

Folder Options > View > Uncheck `Use simple file sharing`

```
\\192.168.1.1\C$
```

# Admin privileges

boot repair disk
    replace `C:\Windows\System32\sethc.exe` with `C:\Windows\System32\cmd.exe`

# Disabled command prompt

.bat file
powershell
https://portableapps.com/apps/utilities/command_prompt_portable
https://forum.raymond.cc/threads/re-enable-project-ideas-and-suggestions.12672/
remove HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System\DisableCMD DWORD 0

# reserved names, special devices, metadata

file:///c:/con/con
c:\con\con
c:\$MFT\123

# fix ntfs corruption

```bash
# From: sudo fdisk -l
sudo ntfsfix /dev/sdb1
# ||
chkdsk /R
```

# windows update

```ps1
# https://docs.microsoft.com/en-us/windows/deployment/update/windows-update-troubleshooting
# https://docs.microsoft.com/en-us/windows/deployment/update/windows-update-logs
# - C:\Windows\Logs\WindowsUpdate\windowsupdate.log
# - C:\ProgramData\USOShared\Logs\UpdateSessionOrchestration.etl
# - C:\ProgramData\USOShared\Logs\NotificationUxBroker.etl
# - $env:systemroot\Logs\CBS\CBS.log
# - $env:windir\System32\catroot2\edb.log

# portable os
# https://superuser.com/questions/1319046/how-do-i-update-windows-10-that-is-installed-on-an-external-hard-disk
# - HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control

# oom - run separate svchost processes
# https://www.reddit.com/r/sysadmin/comments/3w1kfp/windows_update_is_broken_for_w7_x64_ent_wsp1_and/cxso3r4/ 
sc.exe config wuauserv type= own
winmgmt /standalonehost

# supersedence chain

# snapshot - checksums for enumerated files

Get-WindowsUpdateLog

net stop cryptsvc
rename $env:systemroot\system32\catroot2 $env:systemroot\system32\catroot2.bak
net start cryptsvc

net stop wuauserv
net stop bits
rename $env:windir\SoftwareDistribution $env:windir\SoftwareDistribution.bak
net start bits
net start wuauserv
```
# demand-paging model

page directory composed of hierarchy of page tables
    :) efficient handling empty segments of sparse data - only allocates page tables when needed
follow page tables, extract pte, fetch data from ram || hdsk
os compresses memory to maximize ram storage

# dump non public static functions in asemblies

```ps1
ForEach ( $assembly in [AppDomain]::CurrentDomain.GetAssemblies() ) {
    $name = $assembly.FullName.Split(',')[0].ToLower() -Replace('\.',"-")
    $loadTypes = $assembly.GetTypes()
    ForEach ( $type in $loadTypes ) {
        $methods = $type.GetMethods([Reflection.BindingFlags] 'NonPublic, Static') | select -expand Name
        $typeName = $type.FullName
		$outFileName = $name + "." + $typeName
		$assemblyDir = Join-Path (Get-location).Path "assembly"
        $outputFile = Join-path $assemblyDir "${outFileName}"
        Write-Output $methods | out-file -encoding ascii $outputFile
    }
}
```

# File System Redirector

calls to C:\Windows\system32 from 32-bit process redirected to SysWOW64
calls to C:\Windows\Sysnative from 32-bit process redirected to system32 (64 bit)

https://twitter.com/swiftonsecurity/status/988909127006085123

# profiling

On procmon:

- Tools > Profiling Events
- Tools > Stack Summary
- Select: table header > Select Columns > Check: Duration

# installers

EXE
    ```ps1
    # Extract wrapped MSI file
    setup.exe /a
    setup.exe /x
    setup.exe /extract
    ```
MSI - COM-structured storage files, including database
    https://stackoverflow.com/questions/48482545/how-can-i-compare-the-content-of-two-or-more-msi-files/48482546#48482546
    ```ps1
    # Convert to wxs xml
    $OutputFolder=
    dark.exe -x $OutputFolder MySetup.msi
    ```
NSIS (Nullsoft Scriptable Install System)
    /S - run silently
    /D - default installation directory
    https://www.exemsi.com/documentation/installer-frameworks/nsis-nullsoft-scriptable-install-system/

parsing
orca
    Tables > Property
    => Values for public properties
    ||
    Transform > New Transform
    [ Apply Modifications... ]
    Transform > Generate Transform
    => MST file
    ```ps1
    cscript WiUseXfm.vbs $OriginalDatabase $TransformFile $Options
    ```
automating widget manipulation
https://pywinauto.readthedocs.io/en/latest/
https://www.autohotkey.com/docs/commands/ControlGet.htm
    :( Some applications store their ListView text privately, which prevents their text from being retrieved
    e.g. https://autohotkey.com/board/topic/48481-selecting-item-in-combobox/

automating silent install parameters
https://stackoverflow.com/questions/46221983/how-can-i-use-powershell-to-run-through-an-installer
    msiexec.exe /I "C:\Your.msi" /QN /L*V "C:\msilog.log" TRANSFORMS="C:\1031.mst;C:\My.mst"
        https://stackoverflow.com/questions/458857/how-to-make-better-use-of-msi-files/1055861#1055861
        https://stackoverflow.com/questions/54761131/change-the-value-of-a-msi-property-loaded-from-a-dll-using-a-msi-transform/54769767#54769767
        https://docs.microsoft.com/en-us/windows/win32/msi/transforms
    || public properties
    msiexec.exe /I "C:\Your.msi" /QN /L*V "C:\msilog.log" PARAM1="VALUE1" PARAM2="VALUE2"
https://docs.microsoft.com/en-us/windows/win32/msi/standard-installer-command-line-options
https://docs.microsoft.com/en-us/windows/win32/msi/command-line-options

case studies
    chocolatey

# libraries, dll

types
    Visual C++ - Microsoft Foundation Class (MFC) library
        wraps Win32 API calls
        On VC:
        - Configuration Properties > General > Use MFC in static library
        - C/C++ > Code generation > Runtime Library > Multi Threaded Debug
    extension DLL
        derived classes from MFC, built using dynamic-link MFC library
        https://github.com/Microsoft/VCSamples/tree/master/VC2010Samples/MFC/advanced/dllhusk
        https://docs.microsoft.com/en-us/cpp/build/extension-dlls-overview?view=vs-2019
linker pipeline
    .def -(build)-> .exp, .lib
    .exp -(build)-> .dll
exports
    .dll `__declspec(dllexport)` - by name
        import section -(contains)-> .def
    .lib (import library) - by ordinal, assigned automatically, matches function names with ordinals, static library, = stub
        :) enables cross-platform builds (e.g. 64-bit target on 32-bit environment), build for different version of dll given corresponding sdk
        https://stackoverflow.com/questions/1297013/why-do-we-still-need-a-lib-stub-file-when-weve-got-the-actual-dll-implementat
    .def (module-definition) - by ordinal, assigned manually
        :) maintains same ordinals, .lib still valid, no need for apps to relink with .lib
        NONAME attribute - export table stores ordinals instead of function names
            ```c
            const WORD AfxEnableMemoryLeakDumpOrdinal = 15902;
            GetProcAddress( GetModuleHandle( ... ), (LPCSTR)AfxEnableMemoryLeakDumpOrdinal );
            ```
            https://stackoverflow.com/questions/11412650/calling-afxenablememoryleakdump-for-a-specific-mfc-dll
        generated by - https://docs.microsoft.com/en-us/cpp/mfc/reference/mfc-dll-wizard?view=vs-2019
        c++ decorated names (aka. name mangling)
            parsed by - dumpbin, linker /MAP, undname ?func1@a@@AAEXH@Z
            https://docs.microsoft.com/en-us/cpp/build/reference/decorated-names?view=vs-2019
        https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-def-files?view=vs-2019
        ```
        # match ordinal with symbol name
        dumpbin /HEADERS ...\vc98\mfc\lib\MFC42.lib
        # dump symbol names
        dumpbin /EXPORTS foo.dll
        ```
    https://docs.microsoft.com/en-us/cpp/build/exporting-functions-from-a-dll-by-ordinal-rather-than-by-name?view=vs-2019
    https://stackoverflow.com/questions/49157641/pros-and-cons-of-using-def-files
    ui. exports generation depends on sequence of parsed ordinals in .dll and .pdb [MFC42D\.DLL Ordinal vs Name Question · Issue \#316 · NationalSecurityAgency/ghidra · GitHub](https://github.com/NationalSecurityAgency/ghidra/issues/316)
using exported symbols
    LoadLibrary, GetProcAddress - take function addresses from DLL export section manually
logging calls
    proxy dll, dll redirection
    https://stackoverflow.com/a/32959212
preventing dll hijacking
    https://www.fortinet.com/blog/industry-trends/a-crash-course-in-dll-hijacking.html
        registry - SafeDLLSearchMode
    https://github.com/notepad-plus-plus/notepad-plus-plus/commit/b869163609473f05c4f5d1d72a579b9f6af66ccd
        api - CryptQueryObject(), CertFindCertificateInStore(), CertGetNameString() ==  "Notepad++"
    https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-setdefaultdlldirectories
        api - SetDefaultDllDirectories(), AddDllDirectory(), RemoveDllDirectory()
    https://docs.microsoft.com/en-us/security-updates/securityadvisories/2010/2269637

# kerberos

https://serverfault.com/questions/529448/track-down-which-process-program-is-causing-kerberos-pre-authentication-error-c
http://stevenhollidge.blogspot.com/2012/05/troubleshooting-kerberos-with-tools.html

# rsync alternative

robocopy
! limit bandwidth 
    delay = filesize / 64KB * IPG (Inter Packet Gap)
    http://www.zeda.nl/index.php/en/copy-files-on-slow-links
    http://blog.nold.ca/2015/07/limiting-bandwidth-using-robocopy.html

# disable features

https://github.com/W4RH4WK/Debloat-Windows-10
https://github.com/Disassembler0/Win10-Initial-Setup-Script

# break on syscall

1. watch process
2. on syscall, attach to cdb
3. handle syscall
4. kill cdb

# font settings

Control Panel > Adjust ClearType text
Settings > Display > Scale and layout
Settings > Display > Advanced display settings > Advanced sizing of text and other items

# python executables

```bash
sudo apt-get install winetricks
winetricks python26
wget https://www.python.org/ftp/python/2.7.13/python-2.7.13.msi
wine msiexec /i python-2.7.13.msi /L*v log.txt
wine ~/.wine/drive_c/Python27/Scripts/pyinstaller.exe --onefile test.py
```

# bloat, telemetry

```
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f
```


