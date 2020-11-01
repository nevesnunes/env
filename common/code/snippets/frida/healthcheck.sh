#!/usr/bin/env bash

frida -l <(echo "console.log(Java.available);") --no-pause /usr/bin/java
frida -l <(echo "console.log(Module.enumerateImports('ls').map(function(e){return e.name;}))") --no-pause /usr/bin/ls
