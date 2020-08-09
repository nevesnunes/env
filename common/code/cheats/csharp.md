# +

```ps1
# Runtime Environment, .NET Core SDKs, .NET Core runtimes...
dotnet --info
```

```
[DllImport("wldap32.d11", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ldap_ connect")]
internal static extern int ldap_connect(IntPtr ldapHandle, IntPtr timeout);
```

- https://stackoverflow.com/questions/26908049/what-is-net-core

# dissassemble / decompile

- https://github.com/0xd4d/dnSpy
    - .NET assembly editor, decompiler
    - :) debugger
- https://github.com/icsharpcode/ILSpy
    - .NET assembly browser and decompiler
    - :) more plugin support
- http://reflexil.net/
    - .NET assembly editor
- https://github.com/0xd4d/de4dot
    - deobfuscator
