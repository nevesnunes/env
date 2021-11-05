'use strict';

var readPointer = Memory.readPointer;
var readString = Memory.readUtf8String;

var pointerSize = Process.pointerSize;

Interceptor.attach(Module.findExportByName('/usr/lib/system/libsystem_kernel.dylib', '__posix_spawn'), {
  onEnter: function (args) {
    console.log('\n----- Debug -----');
    var path = readString(args[1]);
    console.log('path = ' + path);

    var rawIdentifier = readString(readPointer(args[3].add(pointerSize)));
    console.log('rawIdentifier = ' + rawIdentifier);
  }
});
