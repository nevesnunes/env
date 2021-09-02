# +

- [gdb](./gdb.md)

- http://qira.me/
- https://github.com/rr-debugger/rr
- https://github.com/HyperDbg/HyperDbg
- https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-overview
- https://blog.ret2.io/2021/04/20/tenet-trace-explorer/

- http://man7.org/linux/man-pages/man1/nsenter.1.html

- https://abda.nl/posts/understanding-ptrace/
- https://blog.tartanllama.xyz/writing-a-linux-debugger-setup/
- https://lucasg.github.io/2016/11/27/How-to-Create-and-Debug-a-Process-on-Windows/

# version control

- git blame - reasons behind changes
- issues, pull requests - relate with source code

# methodologies

- predictable attach after running
    > - Because gdbserver is attached to the already running process (as opposed to situation where process would be started by gdbserver) it can miss some code execution which take place soon after the application start.
    > - [...] I usually write some endless while loop and then change the control variable after gdb is fully started.
    - https://mhandroid.wordpress.com/2011/01/25/how-cc-debugging-works-on-android/
- interactive flow control
    > - If there’s a piece of code that’s not doing what you expect, add a loop around it whose condition is a variable that can be modified by the debugger. The resulting binary can be effectively unchanged such that the loop executes once, but if a debugger is present and you see the strange behavior, you can go back and step through it. 1a. This can also be done by modifying the instruction pointer, but that requires restoring register state. I do this too but it’s more tricky.
    > - The unused portion of the stack often contains clues about what happened recently.
    > - Break on access (ba in WinDbg) uses CPU registers to break on a memory address when it’s used. This is wonderful for tracking how state moves across a system, or tracking when locks are acquired and released, etc.
    > - Using breakpoints with conditions allows things like breaking on a common thing, like opening a file, printing out the state of the operation, and resuming execution, allowing interesting conditions to be logged.
    > - While very common, it’s also useful to get a debug memory allocator that can do things like mark pages as invalid on free (to generate access violations on use after free), or add a guard page after a memory allocation (to cause access violations on memory overruns.) A good one of these can also keep around allocation information after free for debugging, such as the stack that freed memory, and track the number of allocations to detect leaks.
    > - Altering thread priorities in the debugger is one way to promote the code you’re trying to look at and/or demote code that’s interfering with you.
    > - If you have a race condition, thoughtfully adding sleep in the right place can provoke it allowing it to be debugged and understood.
    > - If code aborts in ways you don’t expect, add a breakpoint to the exception filter (which decides which handlers to execute.) This executes when the full stack that caused the exception to be raised is present.
    > - Further to the previous comments about patching code, if you’re stepping through code and a branch goes somewhere you don’t want, change the instruction pointer. If you want that branch to happen again, change the condition jump to an unconditional jump.
    > - In WinDbg, dps on import tables or import table entries to show where indirect calls will go. This is useful when something else is trying to hijack your code.
    > - Keep an in memory circular log of interesting cases in your code. This log often doesn’t need to be big, and doesn’t need to allocate on insert, but if something bad happens in your code you can dump the interesting cases that were hit recently.
    - https://lobste.rs/s/h7f6qk/what_debugging_technique_did_it_take_you
- loop until hang/deadlock
    > If you know what part of the code produces it, you iterate over it indefinitely in a debugger until it hangs, then once you notice the iteration has stopped you “step in” to the debugger. Then you run another script that dumps the current trace back for each existing thread. That should be enough to detect the lock normally.
    - https://news.ycombinator.com/item?id=27518087
- Debugging version of malloc/free
    > - The version I use adds guard bytes before and after every allocation, and maintains an "allocated" list which free checks freed chunks against.
    > - Free should fill the freed memory with a known pattern (traditionally, 0xDEADBEEF ) It helps if allocated structures include a "magic number" element, and liberally include checks for the appropriate magic number before using a structure.
    > - verified on delete and causes a program triggered break point which automatically drops me into debugger.
    - https://softwareengineering.stackexchange.com/questions/252696/debugging-memory-corruption/252745
- visualizing internal structures
    > Browse data structures in Firefox. While my Lisp is running, a web browser runs in another thread, and every symbol has its own URL. Data structures are displayed as HTML tables. I can click on a field within an object in Firefox, and it goes to the object contained in that field, and displays that.
    - https://news.ycombinator.com/item?id=11383999
- Complementing static analysis with dynamic analysis
    > You’re going to have to stare at a code listing eventually. The problem is that you want to do it with as much information as possible so as to increase your accuracy. When you normally analyze a code listing for a defect you have some evidence of its existing behaviour: it works when you start with x but not with y, for example. In other words, you have something tangible to work from. Furthermore, those tangible inputs probably came from a system that affects you in some way, giving you a reason to care.
    - [Book review: The puzzling empathy of debugging](https://wozniak.ca/blog/2018/05/07/1/index.html)
- hardware timings
    > - Replace entire modules with stubs that pretend to do the real thing, but actually do something completely trivial that can't be buggy.
    > - Reading and writing (I/O) involves precise timing. [...] the low-level code that reads and writes has to do so according to a clock. [...] I noticed that we set the programmable timer on the PlayStation 1 to 1 kHz (1000 ticks/second) [...] I modified the load/save code to reset the programmable timer to its default setting (100 Hz) before accessing the memory card, then put it back to 1 kHz afterwards. We never saw the read/write problems again.
    > - But the gist of it was that crosstalk between individual parts on the motherboard, and the combination of sending data over both the controller port and the memory card port while running the timer at 1 kHz would cause bits to get dropped... and the data lost... and the card corrupted.
    - https://www.quora.com/Programming-Interviews/Whats-the-hardest-bug-youve-debugged/answer/Dave-Baggett?srid=pxH3&share=1
- timestamped log of problem statement, hypothesis, expected vs actual results
    - http://yellerapp.com/posts/2014-08-11-scientific-debugging.html
- Starting from public-facing API, tracing back to internals
    - https://blog.safia.rocks/post/170269021619/tips-for-reading-new-codebases

### concurrency

- Ensuring atomicity, handling exceptions and reentrant calls:
    ```cpp
    mutex_foo.lock();

    try {
        if (!is_foo_processed) {
            is_foo_processed = true;

            // ...

            // Avoid deadlock on reentrant calls
            mutex_foo.unlock();
            do_foo();
            mutex_foo.lock();

            // ...
        }
    } catch(...) {
        is_foo_processed = false;
        mutex_foo.unlock();
        throw;
    }

    mutex_foo.unlock();
    ```
- https://news.ycombinator.com/item?id=27647340
    > Log as much as you could in the part where you think the bug is. Log every line that's run if you have to. You'll then skim through the log file looking for any unexpected patterns.
        - in-memory logging with thread-id and time stamps
    > ask yourself "what would break if a context switch happens right here" for each line.
    > if you can pinpoint the place where the bug occurs, trigger a SIGSEGV there and run the entire thing under Valgrind.
    > Back on the N64, I updated the bit of code that swapped threads to write, to a ring buffer, the outgoing/incoming PCs, thread IDs and clock. Found tons of unexpected issues. In another thread you can print that or save it to disk or whatever. Or just wait till it crashes and read memory for it. Found the last crash bug with it. Meanwhile, a colleague took it, and drew color coded bars on the screen so we could see exactly what was taking the time.

### reverse debugging / time travel debugging

- [!] `rr` exits using the recorded process' exit code

```bash
echo -1 | sudo tee -a /proc/sys/kernel/perf_event_paranoid
echo 0 | sudo tee -a /proc/sys/kernel/kptr_restrict
rr ./foo
```

- increasing starvation in nondeterministic failures
    - `rr record -h`
        - https://robert.ocallahan.org/2016/02/introducing-rr-chaos-mode.html
        - [1237176 \- Intermittent test\_bfcache\.html \| Test timed out](https://bugzilla.mozilla.org/show_bug.cgi?id=1237176#c41)
        - [1203417 \- Intermittent layout/reftests/scrolling/fixed\-table\-1\.html \| image comparison \(==\), max difference: 165, number of differing pixels: 59976](https://bugzilla.mozilla.org/show_bug.cgi?id=1203417)
        - [1150737 \- Intermittent test\_remove\_objectStore\.html \| Test timed out](https://bugzilla.mozilla.org/show_bug.cgi?id=1150737#c197)
    - `sched_setattr(2)`
        - [GitHub \- osrg/namazu: 鯰: Programmable fuzzy scheduler for testing distributed systems](https://github.com/osrg/namazu)
        - [ZOOKEEPER\-2212: distributed race condition \- Namazu](http://osrg.github.io/namazu/post/zookeeper-2212/)
- atomicity violation for variable s_value
    1. run
    2. reverse-finish
    3. watch s_value
    4. reverse-continue
    - https://www.modernescpp.com/index.php/resolving-c-c-concurrency-bugs-more-efficiently-with-time-travel-debugging
- incorrect size used in page table walk
    1. c
    2. frame 13
    3. break tlb_set_page_with_attrs if vaddr == 0x4012a000
    4. rc
    5. break arm_cpu_handle_mmu_fault
    6. rc
    - https://translatedcode.wordpress.com/2015/05/30/tricks-for-debugging-qemu-rr/
    - https://lists.gnu.org/archive/html/qemu-devel/2015-05/msg05956.html

# case studies

- https://stackoverflow.com/questions/42741370/how-to-debug-nondeterministic-memory-corruption 
    - set a breakpoint on A that sets the write watch on the value and continues execution then have a break point on B that disables the watch; check if value changed
- [Software Folklore ― Andreas Zwinkau](http://beza1e1.tuxen.de/lore/index.html)

### use-after-free

- [Debugging a use\-after\-free in gdb](https://pernos.co/examples/use-after-free)

### ref count

- library not unloading due to ref count bump from call to GetModuleHandleExW()
    - Validation: On WinDbg: `bm *GetModuleHandle*`, proc address argument in library mmap
    - [Debugging a Dynamic Library that Wouldn't Unload \- ForrestTheWoods](https://www.forrestthewoods.com/blog/debugging-a-dynamic-library-that-wouldnt-unload/)

### segv on invalid breakpoints

> This occurs when gdb sets breakpoints on various probe events in the dynamic loader. The probe event locations are exported from ld.so as SDT markers, but gdb needs to know whether ARM or Thumb instructions are being exported at each marker so that it can insert the appropriate breakpoint instruction sequence. It does this by mapping the probe location to a function symbol (see arm_pc_is_thumb in gdb/arm-tdep.c), and using the target address of the symbol to determine if the function is called in Thumb or ARM more (bit 0 of the target address will be set for Thumb mode).
> The problem here is that gdb can't map any of the probes to a symbol if the debug symbols aren't installed, and arm_pc_is_thumb returns false in this case (indicating ARM instructions).
    - [Bug \#1576432 “gdb crashes when trying to start a debugging sessi\.\.\.” : Bugs : gdb](https://bugs.launchpad.net/gdb/+bug/1576432)

### nested symbol lookups unconditionally reset register restoration

```
commit 84088310ce06bfc5759b37f0cd043dce80f578b6
Author: Ulrich Drepper <drepper@redhat.com>
Date:   Tue Aug 25 10:42:30 2009 -0700

    Handle AVX saving on x86-64 in interrupted smbol lookups.

    If a signal arrived during a symbol lookup and the signal handler also
    required a symbol lookup, the end of the lookup in the signal handler reset
    the flag whether restoring AVX/SSE registers is needed.  Resetting means
    in this case that the tail part of the outer lookup code will try to
    restore the registers and this can fail miserably.  We now restore to the
    previous value which makes nesting calls possible.
```

- [519081 &ndash; Random crashes with ld\-linux loader on x86\_64](https://bugzilla.redhat.com/show_bug.cgi?id=519081)

### checksum for replay

> found a bunch of bugs waiting to happen (uninitalized variables / dangling pointer sort of stuff) that would trigger an error when replaying from a file didn't produce the same results as the original play (we had a checksum of game state that we could check)
    - https://news.ycombinator.com/item?id=27517391

### cpu bug

- [772330 \- layout crashes with AuthenticAMD Family 20 \(0x14\), Models 1 and 2 CPUs \(also shows as AMD Radeon HD 6xxx series\), spiking at various times](https://bugzilla.mozilla.org/show_bug.cgi?id=772330#c21)

### shellcmd

[Can&\#39;t open file \(win gvim\) · Issue \#48 · mattn/vim\-gist · GitHub](https://github.com/mattn/gist-vim/issues/48)

This is not a permissions problem, and windows DOES in fact unset read-only. It's just a GUI bug that it thinks the bit is set. If you don't believe me, bring up the command prompt, cd to where the folder is, then do: dir /a:r. The folder you turned read-only off will not appear, because it really IS off.

The problem is really with the system() call. Just doing this from within vim will reproduce it:

```
:echo system("echo hi")
```

The problem is because some shell like cygwin shell is being used. I put these commands at the top of my `_vimrc` file to solve the problem:

```
set shell=cmd
set shellcmdflag=/c
```

This problem is solved now. I am not certain why this fixes it, because it seems like a race condition where the tmp file is created and closed before the process is done using it. The tmp file is in fact created successfully (I saw this with procmon), but it is closed/deleted before it's truely done with it.

### APIs

- Try payload from API response endpoints vs. manually crafted.
