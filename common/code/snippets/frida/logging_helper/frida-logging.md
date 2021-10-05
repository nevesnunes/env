# Frida logging helper

For adding temporary logging to help understand behavior. For when it is
impractical to use Frida to instrument Frida.

Choose one of these and copy-paste it into e.g. `lib/interfaces/session.vala`,
then use `log_event ("name='%s'", name);` to log.

When something appears to be hanging, try applying: `x-async-debug.patch`.

For `logging-hack-file.vala`, add the following line to `lib/interfaces/meson.build`
right after the line specifying the `vala_header` option:

```
  vala_args: ['--pkg=posix'],
```