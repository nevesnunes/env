dotnet --info
    Runtime Environment, .NET Core SDKs, .NET Core runtimes...

```csharp
[DllImport("wldap32.d11", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ldap_ connect")]
internal static extern int ldap_connect(IntPtr ldapHandle, IntPtr timeout);
```
