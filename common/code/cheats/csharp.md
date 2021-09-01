# +

```ps1
# Runtime Environment, .NET Core SDKs, .NET Core runtimes...
dotnet --info
```

```csharp
[DllImport("wldap32.d11", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ldap_ connect")]
internal static extern int ldap_connect(IntPtr ldapHandle, IntPtr timeout);
```

- https://stackoverflow.com/questions/26908049/what-is-net-core
- https://en.wikipedia.org/wiki/List_of_CIL_instructions

# dissassemble / decompile

- https://github.com/0xd4d/dnSpy
    - .NET assembly editor, decompiler
    - :) debugger
- https://github.com/icsharpcode/ILSpy
    - .NET assembly browser and decompiler
    - :) more plugin support
- http://reflexil.net/
    - .NET assembly editor
- https://www.red-gate.com/products/dotnet-development/reflector/
    - .NET decompiler
- https://github.com/0xd4d/de4dot
    - deobfuscator
- https://github.com/HoLLy-HaCKeR/EazFixer
    - deobfuscator for Eazfuscator

# Building

```ps1
# Source
& "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" foo.cs

# Project
& "C:\Program Files (x86)\Microsoft Visual Studio\2017\TeamExplorer\Common7\IDE\devenv.exe" C:\Users\foo\opt\WMIWatcher\WMIWatcher.sln /Build Release
# ||
$env:MSBuildSDKsPath = 'C:\Program Files\dotnet\sdk\3.1.101\Sdks'
& "C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\MSBuild\15.0\Bin\MSBuild.exe" C:\Users\foo\opt\WMIWatcher\WMIWatcher.sln /p:Configuration=Release /t:Restore
# ||
& "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" C:\Users\foo\opt\WMIWatcher\WMIWatcher.sln /p:Configuration=Release /t:Restore
```

- https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/command-line-building-with-csc-exe

# Debug

```ps1
$env:COREHOST_TRACE = 1
```

# References

- [error MSB4236: The SDK &\#39;Microsoft\.NET\.Sdk&\#39; specified could not be found\. · Issue \#2532 · dotnet/msbuild · GitHub](https://github.com/microsoft/msbuild/issues/2532)
