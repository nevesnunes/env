# +

- unix
    - [gdb](./gdb.md)
    - http://qira.me/
    - https://github.com/rr-debugger/rr
    - http://man7.org/linux/man-pages/man1/nsenter.1.html
- windows
    - [windbg](windbg.md)
    - https://github.com/HyperDbg/HyperDbg
    - https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-overview

- [Tenet: A Trace Explorer for Reverse Engineers \| RET2 Systems Blog](https://blog.ret2.io/2021/04/20/tenet-trace-explorer/)
- [GitHub \- bootleg/ret\-sync: ret\-sync is a set of plugins that helps to synchronize a debugging session \(WinDbg/GDB/LLDB/OllyDbg2/x64dbg\) with IDA/Ghidra/Binary Ninja disassemblers\.](https://github.com/bootleg/ret-sync)

# implementation

- breakpoints - single-byte instruction overwritting address
    - https://eli.thegreenplace.net/2011/01/27/how-debuggers-work-part-2-breakpoints
- if no debugger attached, then interrupt handler sends SIGTRAP to threads
    - https://stackoverflow.com/questions/22379105/does-executing-an-int-3-interrupt-stop-the-entire-process-on-linux-or-just-the-c

- https://abda.nl/posts/understanding-ptrace/
- https://blog.tartanllama.xyz/writing-a-linux-debugger-setup/
- https://lucasg.github.io/2016/11/27/How-to-Create-and-Debug-a-Process-on-Windows/

# documentation

- if software wasn't always tracked in vcs, then changelog files document changes in older versions
    - e.g. [CHANGES \- bash\.git \- bash](https://git.savannah.gnu.org/cgit/bash.git/tree/CHANGES)
- documentation isn't as detailed about borrowed semantics as older documentation where they were introduced
    - e.g. ssh vs rlogin escape characters
        - [linux \- Exit SSH connection with user switched inside in one step \- Unix &amp; Linux Stack Exchange](https://unix.stackexchange.com/a/454228/5132)
        - [unix\-history\-repo/cu\.c at usr/src/BSD\-SCCS\-Import · dspinellis/unix\-history\-repo · GitHub](https://github.com/dspinellis/unix-history-repo/blob/usr/src/BSD-SCCS-Import/usr/src/old/cu/cu.c#L29)
- older version of specification may directly address core conceptual issues

### version control

- git bisect - reduce test cases
- git blame - reasons behind changes
- issues, pull requests - relate with source code

### mailing lists

- context / discussion on patches
    - [LKML\.ORG \- the Linux Kernel Mailing List Archive](https://lkml.org/)

### patents

- context on undocumented implementation details
    - e.g. [DEF CON 26 - Christopher Domas - GOD MODE UNLOCKED Hardware Backdoors in redacted x86](https://www.youtube.com/watch?v=jmTwlEh8L7g)

### papers

- start with earliest / most cited, which can describe a different implementation
    - e.g. DNA Cypher - n variants, earliest is "Hiding messages in DNA microdots"

# methodologies

- predictable attach after running
    > - Because gdbserver is attached to the already running process (as opposed to situation where process would be started by gdbserver) it can miss some code execution which take place soon after the application start.
    > - [...] I usually write some endless while loop and then change the control variable after gdb is fully started.
    - https://mhandroid.wordpress.com/2011/01/25/how-cc-debugging-works-on-android/
- USR1 interrupt handler as alternative to attaching under debugger
- interactive flow control
    > - If there’s a piece of code that’s not doing what you expect, add a loop around it whose condition is a variable that can be modified by the debugger. The resulting binary can be effectively unchanged such that the loop executes once, but if a debugger is present and you see the strange behavior, you can go back and step through it. 1a. This can also be done by modifying the instruction pointer, but that requires restoring register state. I do this too but it’s more tricky.
    > - The unused portion of the stack often contains clues about what happened recently.
    > - Break on access (ba in WinDbg) uses CPU registers to break on a memory address when it’s used. This is wonderful for tracking how state moves across a system, or tracking when locks are acquired and released, etc.
    > - Using breakpoints with conditions allows things like breaking on a common thing, like opening a file, printing out the state of the operation, and resuming execution, allowing interesting conditions to be logged.
    > - Altering thread priorities in the debugger is one way to promote the code you’re trying to look at and/or demote code that’s interfering with you.
    > - If you have a race condition, thoughtfully adding sleep in the right place can provoke it allowing it to be debugged and understood.
    > - If code aborts in ways you don’t expect, add a breakpoint to the exception filter (which decides which handlers to execute.) This executes when the full stack that caused the exception to be raised is present.
    > - Further to the previous comments about patching code, if you’re stepping through code and a branch goes somewhere you don’t want, change the instruction pointer. If you want that branch to happen again, change the condition jump to an unconditional jump.
    > - In WinDbg, dps on import tables or import table entries to show where indirect calls will go. This is useful when something else is trying to hijack your code.
    > - Keep an in memory circular log of interesting cases in your code. This log often doesn’t need to be big, and doesn’t need to allocate on insert, but if something bad happens in your code you can dump the interesting cases that were hit recently.
    - https://lobste.rs/s/h7f6qk/what_debugging_technique_did_it_take_you
- finding and logging unique query patterns (check if we've seen it before, how often have we seen it, if it's new, log it)
    - https://florian.github.io/count-min-sketch/
- visualizing internal structures
    > Browse data structures in Firefox. While my Lisp is running, a web browser runs in another thread, and every symbol has its own URL. Data structures are displayed as HTML tables. I can click on a field within an object in Firefox, and it goes to the object contained in that field, and displays that.
    - https://news.ycombinator.com/item?id=11383999
- visualizing layout
    - https://raymii.org/s/articles/Rectangle_debugging_in_QML_just_like_printf.html
- graphics diagnostics - flush screen with color
    > I tried to set the screen color to the value it reads when it exits the loop and then hard-lock so the color doesn’t get changed.
    - https://mgba.io/2020/01/25/infinite-loop-holy-grail/
- reduce watchpoint hits by patching-out instructions
    > - Using the Project64 debugger to set watchpoints on reads or writes to the controller state memory was fruitless because they were constantly triggered by code that I assume was generic system-level code checking and updating the controller state every frame.
    > - Instead I tried a more indirect approach with memory scanning on the Gallery menu. First I tracked down the location of the current button index with the standard technique of repeatedly updating the selection and then scanning memory for the newly changed value. Then I could set read watchpoints on the button index value to see if I could identify where the menu handling code was.
    > - Initially this also caused the watchpoint to trigger repeatedly. By patching out the read instruction that was repeatedly triggered, I saw it was caused by the glowing orange cursor that shows above the currently selected button. After removing that read instruction I got much more useful results: the watchpoint triggered when the menu description text for the currently selected button was changed, and when I pressed A to trigger the currently selected button.
    - https://jamchamb.net/2021/08/17/snap-station.html
- hardware timings
    > - Replace entire modules with stubs that pretend to do the real thing, but actually do something completely trivial that can't be buggy.
    > - Reading and writing (I/O) involves precise timing. [...] the low-level code that reads and writes has to do so according to a clock. [...] I noticed that we set the programmable timer on the PlayStation 1 to 1 kHz (1000 ticks/second) [...] I modified the load/save code to reset the programmable timer to its default setting (100 Hz) before accessing the memory card, then put it back to 1 kHz afterwards. We never saw the read/write problems again.
    > - But the gist of it was that crosstalk between individual parts on the motherboard, and the combination of sending data over both the controller port and the memory card port while running the timer at 1 kHz would cause bits to get dropped... and the data lost... and the card corrupted.
    - https://www.quora.com/Programming-Interviews/Whats-the-hardest-bug-youve-debugged/answer/Dave-Baggett?srid=pxH3&share=1
- checksum for replay
    > found a bunch of bugs waiting to happen (uninitalized variables / dangling pointer sort of stuff) that would trigger an error when replaying from a file didn't produce the same results as the original play (we had a checksum of game state that we could check)
    - https://news.ycombinator.com/item?id=27517391
- complementing static analysis with dynamic analysis
    > You’re going to have to stare at a code listing eventually. The problem is that you want to do it with as much information as possible so as to increase your accuracy. When you normally analyze a code listing for a defect you have some evidence of its existing behaviour: it works when you start with x but not with y, for example. In other words, you have something tangible to work from. Furthermore, those tangible inputs probably came from a system that affects you in some way, giving you a reason to care.
    - [Book review: The puzzling empathy of debugging](https://wozniak.ca/blog/2018/05/07/1/index.html)
- timestamped log of problem statement, hypothesis, expected vs actual results
    - http://yellerapp.com/posts/2014-08-11-scientific-debugging.html
- alternative to reverse debugging: vm snapshots
- general guidelines
    - [Testing and Debugging \- Dr\. Jody Paul](http://jodypaul.com/SWE/TD/TestDebug.html)

### APIs

- Try payload from API response endpoints vs. manually crafted.
- Start from public-facing API, tracing back to internals
    - https://blog.safia.rocks/post/170269021619/tips-for-reading-new-codebases

### memory corruption

- Check locations with no expected writes
    > - Set a breakpoint on A that sets the write watch on the value and continues execution then have a break point on B that disables the watch; check if value changed
    - https://stackoverflow.com/questions/42741370/how-to-debug-nondeterministic-memory-corruption
- Debugging version of malloc/free
    > - The version I use adds guard bytes before and after every allocation, and maintains an "allocated" list which free checks freed chunks against.
    > - Free should fill the freed memory with a known pattern (traditionally, 0xDEADBEEF ) It helps if allocated structures include a "magic number" element, and liberally include checks for the appropriate magic number before using a structure.
    > - verified on delete and causes a program triggered break point which automatically drops me into debugger.
    - https://softwareengineering.stackexchange.com/questions/252696/debugging-memory-corruption/252745
- Trigger access violations
    > - While very common, it’s also useful to get a debug memory allocator that can do things like mark pages as invalid on free (to generate access violations on use after free), or add a guard page after a memory allocation (to cause access violations on memory overruns.) A good one of these can also keep around allocation information after free for debugging, such as the stack that freed memory, and track the number of allocations to detect leaks.
    - https://lobste.rs/s/h7f6qk/what_debugging_technique_did_it_take_you
- Loop around allocations

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
- loop until hang/deadlock
    > If you know what part of the code produces it, you iterate over it indefinitely in a debugger until it hangs, then once you notice the iteration has stopped you “step in” to the debugger. Then you run another script that dumps the current trace back for each existing thread. That should be enough to detect the lock normally.
    - https://news.ycombinator.com/item?id=27518087
- in-memory logging with thread-id and time stamps
    > - Log as much as you could in the part where you think the bug is. Log every line that's run if you have to. You'll then skim through the log file looking for any unexpected patterns.
    > - ask yourself "what would break if a context switch happens right here" for each line.
    > - if you can pinpoint the place where the bug occurs, trigger a SIGSEGV there and run the entire thing under Valgrind.
    > - Back on the N64, I updated the bit of code that swapped threads to write, to a ring buffer, the outgoing/incoming PCs, thread IDs and clock. Found tons of unexpected issues. In another thread you can print that or save it to disk or whatever. Or just wait till it crashes and read memory for it. Found the last crash bug with it. Meanwhile, a colleague took it, and drew color coded bars on the screen so we could see exactly what was taking the time.
    - https://news.ycombinator.com/item?id=27647340

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

- [Reasons why bugs might feel &\#34;impossible&\#34;](https://jvns.ca/blog/2021/06/08/reasons-why-bugs-might-feel-impossible/)
- [What does debugging a program look like?](https://jvns.ca/blog/2019/06/23/a-few-debugging-resources/)
- [Software Folklore ― Andreas Zwinkau](http://beza1e1.tuxen.de/lore/index.html)
- [Category:Games with debugging functions \- The Cutting Room Floor](https://tcrf.net/Category:Games_with_debugging_functions)

```
# specific issues
site:https://github.com AND inurl:issues "race condition"

# dependency usage in other projects
site:https://github.com AND inurl:issues AND -inurl:foo "foo"
```

### reproducing race condition in test

1. [TonYApplicationMaster has race condition where thread is interrupted while flush is happening · Issue \#157 · tony\-framework/TonY · GitHub](https://github.com/tony-framework/TonY/issues/157)
    - `.close()` internally calls `.flush()`, exception thrown when `interrupt()` happens during the `.flush()`
2. [Fix race condition where thread is interrupted while flush is in progress by erwa · Pull Request \#158 · tony\-framework/TonY · GitHub](https://github.com/tony-framework/TonY/pull/158)
    - move `dataFileWriter.close()` call into the `stop()` method, after the event handler thread has terminated.
3. [Add regression test for issue \#157 by nevesnunes · Pull Request \#595 · tony\-framework/TonY · GitHub](https://github.com/tony-framework/TonY/pull/595)
    > This test ensures that when `interrupt()` is called, the EventHandler thread is not calling `dataFileWriter.close()`. In order to have a reproducable test and avoid flakyness, we mock the following methods to ensure the order and timming of the race condition:
    > - `dataFileWriter.close()` is locked on a latch until an `interrupt()` is sent, if that interrupt happens inside this call, it will cause an assertion fail;
    > - `interrupt()` unlocks that latch after executing the real implementation;

### reproducing dangling pointer in game engine

- [prevent appearance of dangling pointers in corpse queue · coelckers/gzdoom@a9ad3d1 · GitHub](https://github.com/coelckers/gzdoom/commit/a9ad3d1fc3c97a0dbf8cbe55bf8b3f9d329c98ea)

### resource leaks

- https://randomascii.wordpress.com/2021/07/25/finding-windows-handle-leaks-in-chromium-and-others/
    - derived measure: outstanding count of handles = created but not deleted across time

### memory corruption

- [Debugging a use\-after\-free in gdb](https://pernos.co/examples/use-after-free)

### bad reference count

- library not unloading due to ref count bump from call to GetModuleHandleExW()
    - Validation: On WinDbg: `bm *GetModuleHandle*`, proc address argument in library mmap
    - [Debugging a Dynamic Library that Wouldn't Unload \- ForrestTheWoods](https://www.forrestthewoods.com/blog/debugging-a-dynamic-library-that-wouldnt-unload/)

### segv on invalid breakpoints

> - This occurs when gdb sets breakpoints on various probe events in the dynamic loader. The probe event locations are exported from ld.so as SDT markers, but gdb needs to know whether ARM or Thumb instructions are being exported at each marker so that it can insert the appropriate breakpoint instruction sequence. It does this by mapping the probe location to a function symbol (see arm_pc_is_thumb in gdb/arm-tdep.c), and using the target address of the symbol to determine if the function is called in Thumb or ARM more (bit 0 of the target address will be set for Thumb mode).
> - The problem here is that gdb can't map any of the probes to a symbol if the debug symbols aren't installed, and arm_pc_is_thumb returns false in this case (indicating ARM instructions).
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
