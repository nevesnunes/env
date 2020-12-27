# Windows

Run with windows powershell admin

```ps1
# Validation
whoami -privs | sls 'SeDebugPrivilege.*Enabled'

frida foo.exe -l "C:\Users\foo\code\snippets\frida\interceptor-backtrace.js"
```

# Debugger

```javascript
session.enable_debugger()
```

# ES6

--enable-jit

# Trace

https://github.com/nowsecure/frida-trace

# Docs

https://www.frida.re/docs/javascript-api/

# +

https://github.com/iddoeldor/frida-snippets
https://awakened1712.github.io/hacking/hacking-frida/
https://www.fuzzysecurity.com/tutorials/29.html
https://sensepost.com/blog/2019/recreating-known-universal-windows-password-backdoors-with-frida/

```javascript
Interceptor.attach(Module.findExportByName(null, "open"), {
  onEnter: function(args) {
    this.file_name = Memory.readCString(ptr(args[0]));
  },
  onLeave: function(retval) {
    if ("your file name" === this.file_name) // passed from onEnter
      retval.replace(0x0); // return null
  }
});
```


