# +

- https://github.com/iddoeldor/frida-snippets
- https://awakened1712.github.io/hacking/hacking-frida/
- https://www.fuzzysecurity.com/tutorials/29.html
- https://sensepost.com/blog/2019/recreating-known-universal-windows-password-backdoors-with-frida/

```bash
frida -l ./foo.js --no-pause ./a.out arg1 arg2
```

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

# Docs

- [JavaScript API \| Frida • A world\-class dynamic instrumentation framework](https://www.frida.re/docs/javascript-api/)

# Build

```bash
git clone --recursive https://github.com/frida/frida.git

alias frida_build="sudo docker run -it --rm -v \$PWD:/frida bannsec/frida_build"
# Give it the same arguments you would give make

# Run all tests for x86_64
frida_build check-gum-linux-x86_64-thin

# Run specific test for V8
frida_build check-gum-linux-x86_64-thin tests=/GumJS/Script/Process/process_nested_signal_handling#V8

# Run specific test for duk
frida_build check-gum-linux-x86_64-thin tests=/GumJS/Script/Process/process_nested_signal_handling#DUK

# Build python3 .so module
frida_build python-linux-x86_64 PYTHON=/usr/bin/python3
```

# Debugger

Client script:

```javascript
session.enable_debugger()
```

- MemoryAccessMonitor

Instrumentation script:

```javascript
while (!Process.isDebuggerAttached()) {
  console.log('Waiting for debugger in PID:', Process.id);
  Thread.sleep(1);
}
```

GUM:

```c
while (!gum_process_is_debugger_attached ()) {
  g_printerr ("Waiting for debugger in PID %u...\n", getpid ());
  g_usleep (G_USEC_PER_SEC);
}
```

- [frida development notes](https://bannsecurity.com/index.php/home/58-frida-development-notes?showall=1)
- [Frida logging hacks · GitHub](https://gist.github.com/oleavr/00d71868d88d597ee322a5392db17af6)

# Tracing

- [GitHub \- nowsecure/frida\-trace: Trace APIs declaratively through Frida\.](https://github.com/nowsecure/frida-trace)

# ES6

```
--enable-jit
```

# Windows

Run with windows powershell admin:

```ps1
# Validation
whoami -privs | sls 'SeDebugPrivilege.*Enabled'

frida foo.exe -l "C:\interceptor-backtrace.js"
```

# iOS

### debuggable

Create debuggable oproject in Xcode, add entitlements

### library injection

Decrypt:

- https://github.com/BishopFox/bfinject
- https://github.com/KJCracks/Clutch

Signing Identity:

- Xcode
  - Preferences > Accounts > Agent > Manage Certificates > iOS Development
  - Target = foo > Signing & Capabilites > Team = $team
  - Take ./embedded.mobileprovision from generated app

Patch:

```bash
security find-identity -p codesigning -v # take $sig

curl -O https://build.frida.re/frida/ios/lib/FridaGadget.dylib
cp FridaGadget.dylib Payload/foo.app/Frameworks

git clone https://github.com/Tyilo/insert_dylib
cd insert_dylib
xcodebuild
./insert_dylib --strip-codesig --inplace '@executable_path/Frameworks/FridaGadget.dylib' Payload/foo.app/foo

codesign -f -v -s  5E25E<snipped-signing-identity> Payload/foo.app/Frameworks/FridaGadget.dylib
zip -qry patchedapp.ipa Payload
npm install -g applesign
applesign -i $sig -m embedded.mobileprovision -o patched_codesign.ipa patchedapp.ipa

npm install -g ios-deploy
mkdir ./patched
cp ./patched_codesign.ipa ./patched/
cd ./patched/
unzip ./patched_codesign.ipa
ios-deploy --bundle Payload/*.app --debug -W

# ||
objection patchipa --source foo.ipa --codesign-signature $sig
ios-deploy --bundle Payload/foo.app -W -d
objection explore

# Validation
frida-ps -Uai
frida -U Gadget
```

- https://medium.com/@dinezh.shetty/setting-up-frida-without-jailbreak-on-devices-running-latest-ios-12-4-27c7cfa6c9a2
- https://labs.f-secure.com/blog/repacking-and-resigning-ios-applications/
