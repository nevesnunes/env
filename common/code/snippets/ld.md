# Parsing

```bash
objdump -T
# ||
nm
```

# Running

```bash
env LD_LIBRARY_PATH=./:$LD_LIBRARY_PATH foo
env LD_PRELOAD="foo.so bar.so" foo

ltrace
```

# Implementation

```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
int kill(pid_t pid, int sig) {
    int (*original_kill)(pid_t, int) = dlsym(RTLD_NEXT, "kill");
    if (pid == 0 && sig == SIGSTOP) {
        /*Don't suspend, initiate resuming*/
        original_kill(0, SIGCONT);
        return 0;
    } else {
        return original_kill(pid, sig);
    }
}
```

```bash
gcc -O -Wall -fPIC -shared -o override_kill.so override_kill.c -dl
env LD_PRELOAD=/path/to/override_kill.so foo
```
